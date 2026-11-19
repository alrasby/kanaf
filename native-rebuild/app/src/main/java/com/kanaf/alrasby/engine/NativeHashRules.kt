package com.kanaf.alrasby.engine

/** Convert ONLY authenticated repository rows to native exact-file rules.
 * Matching the same IOC in three engines is one evidence source, not three.
 */
internal object NativeHashRules {
    private val sha = Regex("[0-9a-f]{64}")
    private val label = Regex("[A-Za-z0-9_.:+-]{1,128}")
    private fun checked(rows: Map<String, String>): List<Map.Entry<String, String>> {
        require(rows.isNotEmpty() && rows.size <= 20_000) { "native-hash-rule-limit" }
        require(rows.all { sha.matches(it.key) && label.matches(it.value) })
        return rows.entries.sortedBy { it.key }
    }
    fun clam(rows: Map<String, String>): ByteArray = checked(rows)
        .joinToString("") { "${it.key}:*:${it.value.replace(':', '_')}:73\n" }.toByteArray(Charsets.US_ASCII)

    fun yara(rows: Map<String, String>): String = checked(rows)
        .mapIndexed { i, row ->
            "rule Kanaf_Updated_Exact_$i { meta: description = \"${row.value}; exact file only\" " +
                "condition: hash.sha256(0, filesize) == \"${row.key}\" }\n"
        }.joinToString("")
}
