package com.kanaf.alrasby.engine

/** Consistent, localized evidence labels. Never upgrade UNKNOWN to safe. */
object ScanEvidenceText {
    fun reason(raw: String, arabic: Boolean): String = when (raw) {
        "native-unavailable-or-limited" -> if (arabic) "لم يُفحص بهذا المحرك بسبب حدود التغطية أو عدم التوافر" else "Engine coverage limit reached or unavailable"
        "file-unreadable-empty-or-size-limit" -> if (arabic) "الملف غير متاح للقراءة أو فارغ أو يتجاوز حد الحجم" else "Unreadable, empty or over the size limit"
        "apk-structure-incomplete" -> if (arabic) "لم يكتمل تحليل بنية APK" else "APK structure analysis incomplete"
        "file-changed-between-engines" -> if (arabic) "تغير الملف بين قراءات المحركات؛ أعد الفحص" else "File changed between engine reads; rescan"
        "copy-size-limit" -> if (arabic) "حجم الملف يتجاوز حد الفحص الأصلي 64 ميجابايت" else "File exceeds the 64 MiB native scan limit"
        "time-limit", "copy-time-limit" -> if (arabic) "انتهت المهلة المحددة للفحص" else "Scan deadline exceeded"
        "cancelled" -> if (arabic) "أوقف المستخدم الفحص" else "Scan cancelled"
        "native-library-unavailable" -> if (arabic) "مكتبة المحرك غير متاحة" else "Native library unavailable"
        "signature-database-unavailable" -> if (arabic) "قاعدة التوقيعات غير متاحة" else "Signature database unavailable"
        else -> raw
    }

    fun hasConflict(decision: EngineConsensus.Decision): Boolean =
        decision is EngineConsensus.Decision.Inconclusive &&
            decision.reason == "file-changed-between-engines"

    fun nativeLabel(name: String, verdict: AntivirusEngine.Verdict,
                    conflict: Boolean, arabic: Boolean = true): String =
        if (arabic) when (verdict) {
            is AntivirusEngine.Verdict.Detected -> if (conflict)
                "$name: رُصد تطابق (${verdict.threatName}) في قراءة منفصلة، ولا يمكن تأكيده على النسخة الحالية."
                else if (ThreatFamily.classify(verdict.threatName) == ThreatFamily.Kind.TEST_SAMPLE)
                    "$name: كشف عينة EICAR الاختبارية — ${verdict.threatName}"
                else "$name: تطابق توقيع ${verdict.threatName} — ${ThreatFamily.label(verdict.threatName, true)}"
            is AntivirusEngine.Verdict.NoKnownMatch -> if (conflict)
                "$name: لم يظهر تطابق في قراءة منفصلة؛ النتيجة غير معتمدة للحكم على الملف الحالي."
                else "$name: لا تطابق مع القواعد المحملة؛ السلامة غير مؤكدة"
            is AntivirusEngine.Verdict.Incomplete -> "$name: لم يكتمل الفحص (${reason(verdict.reason, arabic)})"
        } else when (verdict) {
            is AntivirusEngine.Verdict.Detected -> if (conflict)
                "$name: A signature match (${verdict.threatName}) appeared on a separate read; it cannot be confirmed for the current file."
                else if (ThreatFamily.classify(verdict.threatName) == ThreatFamily.Kind.TEST_SAMPLE)
                    "$name: Harmless EICAR test detection — ${verdict.threatName}"
                else "$name: Signature match ${verdict.threatName} — ${ThreatFamily.label(verdict.threatName, false)}"
            is AntivirusEngine.Verdict.NoKnownMatch -> if (conflict)
                "$name: No match appeared on a separate read; this does not certify the current file."
                else "$name: No match in the loaded rules; safety unverified"
            is AntivirusEngine.Verdict.Incomplete -> "$name: Scan incomplete (${reason(verdict.reason, arabic)})"
        }

    fun hashLabel(verdict: AntivirusEngine.Verdict, count: Int,
                  conflict: Boolean, arabic: Boolean = true): String =
        if (arabic) when (verdict) {
            is AntivirusEngine.Verdict.Detected -> if (conflict)
                "رُصد تطابق (${verdict.threatName}) في قراءة SHA-256 منفصلة؛ لا يمكن تأكيده على النسخة الحالية.\nSHA-256: ${verdict.sha256}"
                else (if (verdict.threatName.contains("eicar", true))
                    "تطابق عينة اختبار EICAR الآمنة"
                    else "تطابق توقيع تهديد: ${verdict.threatName} — ${ThreatFamily.label(verdict.threatName, true)}") + "\nSHA-256: ${verdict.sha256}"
            is AntivirusEngine.Verdict.NoKnownMatch -> if (conflict)
                "لم يظهر تطابق في قراءة SHA-256 منفصلة ضمن $count توقيع محلي؛ هذه ليست نتيجة سلامة.\nSHA-256: ${verdict.sha256}"
                else "لم يُعثر على تطابق في $count توقيع محلي. هذا لا يعني أن الملف آمن.\nSHA-256: ${verdict.sha256}"
            is AntivirusEngine.Verdict.Incomplete -> "الفحص غير مكتمل: ${reason(verdict.reason, true)}"
        } else when (verdict) {
            is AntivirusEngine.Verdict.Detected -> if (conflict)
                "SHA-256 match (${verdict.threatName}) on a separate read; not verified for the current file.\nSHA-256: ${verdict.sha256}"
                else (if (verdict.threatName.contains("eicar", true))
                    "Harmless EICAR test sample matched"
                    else "Known threat signature match: ${verdict.threatName} — ${ThreatFamily.label(verdict.threatName, false)}") + "\nSHA-256: ${verdict.sha256}"
            is AntivirusEngine.Verdict.NoKnownMatch -> if (conflict)
                "No match in $count local SHA-256 signatures on a separate read; this does not certify safety.\nSHA-256: ${verdict.sha256}"
                else "No match among $count local signatures. This does not prove safety.\nSHA-256: ${verdict.sha256}"
            is AntivirusEngine.Verdict.Incomplete -> "Scan incomplete: ${reason(verdict.reason, false)}"
        }
}
