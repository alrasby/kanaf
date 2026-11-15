package com.kanaf.alrasby.engine

/**
 * In-memory-only history for optional user-visible scan summaries.
 * The caller must never supply file names, URIs or raw file content.
 */
internal object SessionHistoryPolicy {
    fun record(history: MutableList<String>, result: String, enabled: Boolean) {
        if (!enabled) return
        history.add(0, result.lineSequence().take(3).joinToString("\n").take(600))
        while (history.size > 10) history.removeAt(history.lastIndex)
    }
}
