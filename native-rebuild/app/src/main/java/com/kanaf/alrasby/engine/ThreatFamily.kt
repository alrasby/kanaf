package com.kanaf.alrasby.engine

/**
 * A family is displayed ONLY for an actual verified signature label. These
 * are labels from the feed author, not behavioral malware detection.
 * Unknown labels are NEVER guessed from filenames or permissions.
 */
object ThreatFamily {
    enum class Kind { BACKDOOR, TROJAN, RANSOMWARE, SPYWARE, ADWARE, WORM, ROOTKIT,
        KEYLOGGER, BOTNET, MINER, DROPPER, EXPLOIT, TEST_SAMPLE, UNCLASSIFIED }

    fun classify(signature: String): Kind {
        val prefix = signature.trim().substringBefore('.').substringBefore(':')
            .substringBefore('-').lowercase(java.util.Locale.ROOT)
        return when (prefix) {
            "backdoor" -> Kind.BACKDOOR
            "trojan" -> Kind.TROJAN
            "ransomware" -> Kind.RANSOMWARE
            "spyware" -> Kind.SPYWARE
            "adware" -> Kind.ADWARE
            "worm" -> Kind.WORM
            "rootkit" -> Kind.ROOTKIT
            "keylogger" -> Kind.KEYLOGGER
            "botnet" -> Kind.BOTNET
            "miner", "coinminer", "cryptominer" -> Kind.MINER
            "dropper" -> Kind.DROPPER
            "exploit" -> Kind.EXPLOIT
            "eicar", "kanaf_eicar", "kanaf" ->
                if (signature.contains("eicar", ignoreCase = true)) Kind.TEST_SAMPLE
                else Kind.UNCLASSIFIED
            else -> Kind.UNCLASSIFIED
        }
    }

    fun label(signature: String, arabic: Boolean): String = when (classify(signature)) {
        Kind.BACKDOOR -> if (arabic) "باب خلفي" else "Backdoor"
        Kind.TROJAN -> if (arabic) "حصان طروادة" else "Trojan"
        Kind.RANSOMWARE -> if (arabic) "برمجية فدية" else "Ransomware"
        Kind.SPYWARE -> if (arabic) "برنامج تجسس" else "Spyware"
        Kind.ADWARE -> if (arabic) "برنامج إعلانات" else "Adware"
        Kind.WORM -> if (arabic) "دودة" else "Worm"
        Kind.ROOTKIT -> if (arabic) "روتكِت" else "Rootkit"
        Kind.KEYLOGGER -> if (arabic) "تسجيل ضغطات المفاتيح" else "Keylogger"
        Kind.BOTNET -> if (arabic) "شبكة بوت" else "Botnet"
        Kind.MINER -> if (arabic) "تعدين خفي" else "Cryptominer"
        Kind.DROPPER -> if (arabic) "أداة إسقاط برمجيات" else "Dropper"
        Kind.EXPLOIT -> if (arabic) "استغلال ثغرة" else "Exploit"
        Kind.TEST_SAMPLE -> if (arabic) "عينة اختبار غير ضارة" else "Harmless test sample"
        Kind.UNCLASSIFIED -> if (arabic) "فئة غير محددة من التوقيع" else "Unclassified signature label"
    }
}
