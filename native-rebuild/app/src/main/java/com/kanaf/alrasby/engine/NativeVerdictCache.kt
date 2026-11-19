package com.kanaf.alrasby.engine

/** Process-local LRU. Call only AFTER hashing an immutable full file snapshot.
 * The key binds content, both rulesets, engines and scan policy. Never caches
 * failures or uses path/mtime/size as proof that the content is unchanged.
 */
internal class NativeVerdictCache(private val capacity: Int = 128) {
    init { require(capacity in 1..512) }
    data class Key(val fileSha256: String, val clamRules: String, val yaraRules: String,
                   val policy: String = "clam1.4.6-yarax0.13.0-64MiB-policy-v1")
    private val entries = object : LinkedHashMap<Key, Pair<AntivirusEngine.Verdict, AntivirusEngine.Verdict>>(16, .75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Key, Pair<AntivirusEngine.Verdict, AntivirusEngine.Verdict>>?) = size > capacity
    }
    @Synchronized fun get(key: Key) = entries[key]
    @Synchronized fun put(key: Key, clam: AntivirusEngine.Verdict, yara: AntivirusEngine.Verdict) {
        if (clam is AntivirusEngine.Verdict.Incomplete || yara is AntivirusEngine.Verdict.Incomplete) return
        fun digest(verdict: AntivirusEngine.Verdict) = when (verdict) {
            is AntivirusEngine.Verdict.Detected -> verdict.sha256
            is AntivirusEngine.Verdict.NoKnownMatch -> verdict.sha256
            is AntivirusEngine.Verdict.Incomplete -> ""
        }
        require(digest(clam) == key.fileSha256 && digest(yara) == key.fileSha256)
        entries[key] = clam to yara
    }
}
