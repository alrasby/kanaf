package com.kanaf.alrasby.engine

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/** Local certificate/permission history; rotation is checked against Android's
 * signing lineage before raising a changed-certificate warning. */
object PackageBaseline {
    data class Snapshot(val version: Long, val certificates: Set<String>, val permissions: Set<String>)
    data class Change(val baselineExists: Boolean, val addedPermissions: Set<String>, val unverifiedSignerChange: Boolean)
    private fun prefs(context: Context) = context.getSharedPreferences("kanaf_package_baselines", Context.MODE_PRIVATE)
    private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }

    @Suppress("DEPRECATION")
    fun snapshot(context: Context, name: String): Snapshot {
        val flags = PackageManager.GET_PERMISSIONS or if (Build.VERSION.SDK_INT >= 28)
            PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
        val info = context.packageManager.getPackageInfo(name, flags)
        val certs = if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners
            else info.signatures
        require(!certs.isNullOrEmpty()) { "signing-certificate-unavailable" }
        return Snapshot(if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong(),
            certs.map { digest(it.toByteArray()) }.toSet(), info.requestedPermissions.orEmpty().toSet())
    }

    fun compare(previous: Snapshot?, current: Snapshot, lineageVerified: Boolean): Change = Change(
        previous != null, current.permissions - (previous?.permissions ?: current.permissions),
        previous != null && previous.certificates != current.certificates && !lineageVerified)

    fun read(context: Context, name: String): Snapshot? = prefs(context).getString(name, null)?.let { text ->
        runCatching {
            val json = JSONObject(text)
            fun strings(key: String): Set<String> = json.getJSONArray(key).let { array ->
                (0 until array.length()).map { array.getString(it) }.toSet()
            }
            Snapshot(json.getLong("version"), strings("certificates"), strings("permissions"))
        }.getOrNull()
    }

    fun inspect(context: Context, name: String, current: Snapshot): Change {
        val previous = read(context, name)
        val lineage = previous != null && previous.certificates.size == 1 && current.certificates.size == 1 &&
            Build.VERSION.SDK_INT >= 28 && previous.certificates.all { hex ->
                val bytes = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
                context.packageManager.hasSigningCertificate(name, bytes, PackageManager.CERT_INPUT_SHA256)
            }
        return compare(previous, current, lineage)
    }

    fun save(context: Context, name: String, snapshot: Snapshot) {
        val store = prefs(context)
        // Bound local history. Never upload the user's app inventory.
        if (!store.contains(name) && store.all.size >= 2500) return
        val value = JSONObject().put("version", snapshot.version)
            .put("certificates", JSONArray(snapshot.certificates.sorted()))
            .put("permissions", JSONArray(snapshot.permissions.sorted())).toString()
        check(store.edit().putString(name, value).commit()) { "package-baseline-save-failed" }
    }
}
