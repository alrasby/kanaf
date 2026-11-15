package com.kanaf.alrasby.engine

import android.content.Context
import android.net.Uri
import com.kanaf.alrasby.BuildConfig
import java.io.IOException
import java.util.Base64

/**
 * ONLY installation of an authenticated, offline feed. It does not fetch data
 * from remote URLs. The production PUBLIC key must be provisioned at build time.
 */
class ProductionFeedInstaller {
    fun configured(): Boolean = BuildConfig.KANAF_SIGNATURE_PUBLIC_KEY_BASE64.isNotBlank()

    fun importSignedZip(context: Context, uri: Uri): Long {
        if (!configured()) throw IOException("production-signing-key-not-configured")
        if (uri.scheme != "content") throw IOException("SAF-file-required")
        val publicKey = Base64.getDecoder()
            .decode(BuildConfig.KANAF_SIGNATURE_PUBLIC_KEY_BASE64)
        val file = context.contentResolver.openInputStream(uri)
            ?: throw IOException("feed-unavailable")
        val parsed = file.use { SignedFeedPackage.parse(it) }
        SignatureRepository(context).installVerified(parsed.bytes, parsed.manifest, publicKey)
        return parsed.manifest.version
    }
}
