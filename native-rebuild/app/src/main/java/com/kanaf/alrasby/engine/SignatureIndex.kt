package com.kanaf.alrasby.engine

import java.io.BufferedReader
import java.io.Reader

/** Strict, local SHA-256 feed parser. Input format: sha256<TAB>label. */
object SignatureIndex {
    private val sha256 = Regex("^[0-9a-fA-F]{64}$")
    private val label = Regex("^[a-zA-Z0-9_.:+-]{1,128}$")

    fun parse(reader: Reader, maxEntries: Int = 500_000): Map<String, String> {
        require(maxEntries > 0)
        val records = HashMap<String, String>()
        BufferedReader(reader).use { lines ->
            lines.forEachLine { line ->
                if (line.isBlank() || line.startsWith("#")) return@forEachLine
                val fields = line.split('\t')
                require(fields.size == 2 && sha256.matches(fields[0]) && label.matches(fields[1])) {
                    "Invalid signature entry"
                }
                val digest = fields[0].lowercase()
                val previous = records.putIfAbsent(digest, fields[1])
                require(previous == null || previous == fields[1]) { "Conflicting signature" }
                require(records.size <= maxEntries) { "Signature limit exceeded" }
            }
        }
        return records
    }
}
