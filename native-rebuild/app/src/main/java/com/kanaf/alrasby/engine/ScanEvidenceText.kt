package com.kanaf.alrasby.engine

/** Consistent and testable user-facing labels for potentially different SAF reads. */
object ScanEvidenceText {
    fun hasConflict(decision: EngineConsensus.Decision): Boolean =
        decision is EngineConsensus.Decision.Inconclusive &&
            decision.reason == "file-changed-between-engines"

    fun nativeLabel(name: String, verdict: AntivirusEngine.Verdict, conflict: Boolean): String =
        when (verdict) {
            is AntivirusEngine.Verdict.Detected -> if (conflict)
                "$name: رُصد تطابق (${verdict.threatName}) في قراءة منفصلة، ولا يمكن تأكيده على النسخة الحالية."
                else "$name: كشف تجريبي EICAR — ${verdict.threatName}"
            is AntivirusEngine.Verdict.NoKnownMatch -> if (conflict)
                "$name: لم يظهر تطابق في قراءة منفصلة؛ النتيجة غير معتمدة للحكم على الملف الحالي."
                else "$name: لا تطابق مع قاعدة EICAR الاختبارية"
            is AntivirusEngine.Verdict.Incomplete -> "$name: لم يكتمل الفحص (${verdict.reason})"
        }

    fun hashLabel(verdict: AntivirusEngine.Verdict, count: Int, conflict: Boolean): String =
        when (verdict) {
            is AntivirusEngine.Verdict.Detected -> if (conflict)
                "رُصد تطابق (${verdict.threatName}) في قراءة SHA-256 منفصلة؛ لا يمكن تأكيده على النسخة الحالية.\nSHA-256: ${verdict.sha256}"
                else (if (verdict.threatName.contains("eicar", true))
                    "تطابق عينة اختبار EICAR الآمنة"
                    else "تطابق توقيع تهديد: ${verdict.threatName}") + "\nSHA-256: ${verdict.sha256}"
            is AntivirusEngine.Verdict.NoKnownMatch -> if (conflict)
                "لم يظهر تطابق في قراءة SHA-256 منفصلة ضمن $count توقيع محلي؛ هذه ليست نتيجة سلامة.\nSHA-256: ${verdict.sha256}"
                else "لم يُعثر على تطابق في $count توقيع محلي. هذا لا يعني أن الملف آمن.\nSHA-256: ${verdict.sha256}"
            is AntivirusEngine.Verdict.Incomplete -> "الفحص غير مكتمل: ${verdict.reason}"
        }
}
