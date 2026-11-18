package com.kanaf.alrasby.engine

/**
 * Versioned, bounded inputs for a future on-device ML classifier.
 * No model is bundled or inferred here. Unknown observations remain unknown.
 */
data class ThreatFeatureVector(
    val schemaVersion: Int = 1,
    val apkDexCount: Int?,
    val apkNativeLibraryCount: Int?,
    val apkUnsafePathCount: Int?,
    val dexInvalidHeaderCount: Int?,
    val zipUnsafeNameCount: Int?,
    val zipEntryCount: Int?,
    val zipExpandedBytes: Long?
) {
    init {
        require(schemaVersion == 1)
        require(listOfNotNull(apkDexCount, apkNativeLibraryCount, apkUnsafePathCount,
            dexInvalidHeaderCount, zipUnsafeNameCount, zipEntryCount).all { it >= 0 })
        require(zipExpandedBytes == null || zipExpandedBytes >= 0)
    }

    companion object {
        fun from(
            apk: ApkStructureInspector.Result?,
            dex: DexHeaderInspector.Result?,
            zip: ZipInspector.Result?
        ): ThreatFeatureVector {
            val a = (apk as? ApkStructureInspector.Result.Complete)?.summary
            val d = (dex as? DexHeaderInspector.Result.Complete)?.summary
            val z = (zip as? ZipInspector.Result.Complete)?.summary
            return ThreatFeatureVector(
                apkDexCount = a?.dexFiles,
                apkNativeLibraryCount = a?.nativeLibraries,
                apkUnsafePathCount = a?.unsafePaths,
                dexInvalidHeaderCount = d?.invalidHeaders,
                zipUnsafeNameCount = z?.unsafeNames,
                zipEntryCount = z?.entries,
                zipExpandedBytes = z?.bytesExpanded
            )
        }
    }

    /** A classifier must not mistake an absent scan for a measured zero. */
    fun hasAnyObservation(): Boolean = listOf(apkDexCount, apkNativeLibraryCount,
        apkUnsafePathCount, dexInvalidHeaderCount, zipUnsafeNameCount,
        zipEntryCount, zipExpandedBytes).any { it != null }
}
