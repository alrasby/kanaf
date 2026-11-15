package com.kanaf.alrasby

import android.content.Context
import java.util.Locale

/**
 * Local-first presentation settings. No contact/network permissions or
 * independent task execution. Stored only inside this app's private prefs.
 */
enum class KanafLanguage(val storedValue: String) {
    SYSTEM("system"), ARABIC("ar"), ENGLISH("en");

    companion object {
        fun fromStored(value: String?): KanafLanguage =
            entries.firstOrNull { it.storedValue == value } ?: SYSTEM
    }

    fun resolvedLocale(system: Locale = Locale.getDefault()): Locale = when (this) {
        ARABIC -> Locale.forLanguageTag("ar")
        ENGLISH -> Locale.ENGLISH
        SYSTEM -> if (system.language == "ar") Locale.forLanguageTag("ar") else Locale.ENGLISH
    }

    fun isArabic(system: Locale = Locale.getDefault()) =
        resolvedLocale(system).language == "ar"
}

/** Navigation options with stable IDs, independent of translated labels/order. */
enum class KanafSection(val page: Int, val id: String) {
    SCAN(0, "scan"),
    LINKS(1, "links"),
    APPS(7, "apps"),
    VAULT(6, "vault"),
    PROTECTION(8, "protection"),
    HISTORY(2, "history"),
    ENGINES(3, "engines");

    companion object {
        val OPTIONAL = entries.filter { it != SCAN }
        fun fromId(id: String): KanafSection? = entries.firstOrNull { it.id == id }
    }
}

class KanafUiPreferences(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences(
        "kanaf_presentation_v1", Context.MODE_PRIVATE
    )

    fun language(): KanafLanguage =
        KanafLanguage.fromStored(prefs.getString("language", "system"))

    fun hiddenSections(): Set<String> =
        prefs.getStringSet("hidden", emptySet()).orEmpty()
            .filter { id -> KanafSection.OPTIONAL.any { it.id == id } }.toSet()

    fun setLanguage(language: KanafLanguage) {
        check(prefs.edit().putString("language", language.storedValue).commit()) {
            "Could not store language preference"
        }
    }

    fun setSectionVisible(section: KanafSection, visible: Boolean) {
        require(section != KanafSection.SCAN) { "Scan must remain accessible" }
        val updated = hiddenSections().toMutableSet()
        if (visible) updated.remove(section.id) else updated.add(section.id)
        check(prefs.edit().putStringSet("hidden", updated.toSet()).commit()) {
            "Could not store navigation preference"
        }
    }
}

/** Keep both translations for in-session status updates and scan history.
 * Switching language is therefore instant even for results already shown. */
data class KanafMessage(val ar: String, val en: String) {
    fun displayed(language: KanafLanguage): String =
        if (language.isArabic()) ar else en

    fun append(suffix: String): KanafMessage =
        KanafMessage(ar + suffix, en + suffix)

    companion object {
        val EMPTY = KanafMessage("", "")
        fun combine(lines: List<KanafMessage>): KanafMessage = KanafMessage(
            lines.map { it.ar }.filter { it.isNotBlank() }.joinToString("\n"),
            lines.map { it.en }.filter { it.isNotBlank() }.joinToString("\n")
        )
    }
}
