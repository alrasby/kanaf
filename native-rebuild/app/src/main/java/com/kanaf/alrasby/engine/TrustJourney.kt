package com.kanaf.alrasby.engine

/** User-facing decision guidance derived only from evidence we actually collected. */
object TrustJourney {
    enum class Action { STOP_AND_VERIFY, REVIEW_BEFORE_INSTALLING, RETRY_SCAN, VERIFY_SOURCE }
    data class Card(
        val action: Action,
        val title: String,
        val explanation: String,
        val nextStep: String
    )
    fun build(
        assessment: ThreatEvidence.Assessment,
        scanCompleted: Boolean,
        signaturesAvailable: Boolean
    ): Card {
        if (assessment.severity == ThreatEvidence.Severity.CONFIRMED) {
            return Card(Action.STOP_AND_VERIFY, "تطابق توقيع تهديد معروف",
                "تطابق الملف مع توقيع محلي مسجل. تحقق من مصدر قاعدة التوقيعات.",
                "لا تثبّت الملف. راجع المصدر واطلب فحصًا إضافيًا قبل أي حذف.")
        }
        if (assessment.severity == ThreatEvidence.Severity.SUSPICIOUS) {
            return Card(Action.REVIEW_BEFORE_INSTALLING, "مؤشرات تحتاج إلى مراجعة",
                "رُصدت خصائص بنيوية غير اعتيادية؛ لا تثبت وحدها وجود برمجية خبيثة.",
                "تحقق من ناشر الملف ومصدره ولا تمنحه صلاحيات حساسة قبل التحقق.")
        }
        if (!scanCompleted || !signaturesAvailable ||
            assessment.severity == ThreatEvidence.Severity.INCONCLUSIVE) {
            return Card(Action.RETRY_SCAN, "التحليل غير مكتمل",
                "لم تُفحص كل الأدلة المطلوبة، أو تعذّر تحميل قاعدة التوقيعات.",
                "أعد الفحص بعد معالجة السبب، ولا تعتبر النتيجة شهادة سلامة.")
        }
        return Card(Action.VERIFY_SOURCE, "لا يوجد تطابق معروف",
            "لم تُرصد مؤشرات ضمن الفحوص المتاحة؛ قد تبقى تهديدات غير مكتشفة.",
            "تحقق من المصدر والتوقيع الرقمي للتطبيق قبل تثبيته.")
    }
}
