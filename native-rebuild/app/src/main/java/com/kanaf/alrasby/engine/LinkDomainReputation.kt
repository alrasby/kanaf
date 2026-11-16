package com.kanaf.alrasby.engine

import java.io.IOException
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import org.json.JSONException
import org.json.JSONObject

internal object LinkDomainReputation {
    enum class Result { BLOCKED, NOT_BLOCKED, UNAVAILABLE }

    private val label = Regex("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
    private val privateSuffixes = setOf("local", "localhost", "internal", "onion", "test", "invalid")

    fun supports(host: String): Boolean {
        val labels = host.split('.')
        return host.length <= 253 && labels.size >= 2 && labels.all(label::matches) &&
            labels.last().any { it in 'a'..'z' } && labels.last() !in privateSuffixes
    }

    fun check(host: String): Result {
        if (!supports(host)) return Result.UNAVAILABLE
        val endpoint = URL("https://security.cloudflare-dns.com/dns-query?name=$host&type=A")
        val connection = endpoint.openConnection() as HttpsURLConnection
        return try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 3000
            connection.readTimeout = 3000
            connection.useCaches = false
            connection.setRequestProperty("Accept", "application/dns-json")
            if (connection.responseCode != 200) return Result.UNAVAILABLE
            val buffer = CharArray(8193)
            val count = connection.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                var length = 0
                while (length < buffer.size) {
                    val read = reader.read(buffer, length, buffer.size - length)
                    if (read < 0) break
                    length += read
                }
                length
            }
            if (count >= buffer.size) Result.UNAVAILABLE
            else classify(host, JSONObject(String(buffer, 0, count)))
        } catch (_: IOException) {
            Result.UNAVAILABLE
        } catch (_: JSONException) {
            Result.UNAVAILABLE
        } catch (_: SecurityException) {
            Result.UNAVAILABLE
        } finally {
            connection.disconnect()
        }
    }

    internal fun classify(host: String, response: JSONObject): Result {
        if (response.optInt("Status", -1) != 0 || response.optBoolean("TC"))
            return Result.UNAVAILABLE
        val question = response.optJSONArray("Question")?.optJSONObject(0)
            ?: return Result.UNAVAILABLE
        if (!question.optString("name").trimEnd('.').equals(host, ignoreCase = true) ||
            question.optInt("type") != 1) return Result.UNAVAILABLE
        val answers = response.optJSONArray("Answer") ?: return Result.UNAVAILABLE
        var hasAddress = false
        for (index in 0 until answers.length()) {
            val answer = answers.optJSONObject(index) ?: continue
            if (answer.optInt("type") != 1) continue
            val address = answer.optString("data")
            if (address == "0.0.0.0") return Result.BLOCKED
            val octets = address.split('.')
            if (octets.size == 4 && octets.all { it.toIntOrNull()?.let { n -> n in 0..255 } == true })
                hasAddress = true
        }
        return if (hasAddress) Result.NOT_BLOCKED else Result.UNAVAILABLE
    }
}
