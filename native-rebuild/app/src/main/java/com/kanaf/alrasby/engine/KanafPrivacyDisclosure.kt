package com.kanaf.alrasby.engine

import com.kanaf.alrasby.BuildConfig

/**
 * Honest, affirmative in-app disclosures for BOTH DNS entry points.
 * The HTTPS DNS provider is an independent third party; the app cannot
 * promise that the provider keeps no DNS logs.
 */
object KanafPrivacyDisclosure {
    const val VPN_TITLE_AR = "موافقة منفصلة على خدمة DNS وVPN"
    const val VPN_TITLE_EN = "Separate DNS and VPN consent"

    val VPN_AR = if (BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY) {
        "عند تفعيل Kanaf DNS ينشئ أندرويد نفق VPN محليًا لاستعلامات DNS الموجهة إليه فقط، " +
        "ولا يفحص محتوى HTTPS. تُرسل الاستعلامات المسموح بها مشفرة عبر HTTPS إلى Cloudflare " +
        "للحماية من نطاقات البرمجيات الخبيثة والتصيد فقط، وليس لحجب الإعلانات. " +
        "قد يرى Cloudflare أسماء النطاقات وعنوان اتصالك وفق سياسة خصوصيته. " +
        "لا يحتفظ كنف بسجل أسماء النطاقات؛ العدادات مؤقتة للجلسة فقط. " +
        "لا يمكن تشغيل VPN آخر بالتزامن، ويمكن إيقاف كنف في أي وقت. " +
        "هل توافق صراحةً على استخدام VPN وإرسال استعلامات DNS إلى Cloudflare؟"
    } else "عند تفعيل Kanaf DNS ينشئ أندرويد نفق VPN محليًا لحركة DNS الموجهة إليه فقط، " +
        "وليس لتصفح الإنترنت أو محتوى HTTPS. تُفحص نطاقات DNS محليًا للحجب، " +
        "وتُرسل الطلبات المسموح بها مشفّرة عبر HTTPS إلى مزوّد AdGuard DNS الذي تختاره. " +
        "قد يرى المزوّد نطاقات الاستعلام وعنوان اتصالك وفق سياسة خصوصيته. " +
        "لا يحتفظ كنف بسجل نطاقات DNS، ويعرض عدادات مؤقتة للجلسة. " +
        "قد يمنع المرشح نطاقات إعلانية وتتبعية في تطبيقات أخرى، وقد تتجاوز بعض التطبيقات الحجب. " +
        "لا يمكن تشغيل VPN آخر معه، ويمكنك إيقافه في أي وقت. " +
        "هل توافق صراحةً على تشغيل VPN المحلي وإرسال طلبات DNS للمزوّد المحدد؟"

    val VPN_EN = if (BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY) {
        "Kanaf DNS uses an Android local VPN only for DNS queries addressed to its resolver. " +
        "It does not inspect HTTPS content. Allowed DNS queries travel over encrypted HTTPS " +
        "to independent Cloudflare security DNS for malware and phishing protection only, " +
        "NOT ad or tracker blocking. Cloudflare may see queried domains and your connecting IP " +
        "under its privacy policy. Optional DNS diagnostics retain up to 64 events in RAM until stop or disable; session counters are " +
        "temporary. Other VPNs cannot operate simultaneously. You can stop Kanaf at any time. " +
        "Do you explicitly agree to use the local VPN and send DNS queries to Cloudflare?"
    } else "Kanaf DNS creates an Android local VPN for DNS queries addressed to its resolver only; " +
        "it does not inspect HTTPS content or route general browsing traffic. " +
        "Kanaf checks DNS names locally for blocking and sends allowed queries over encrypted HTTPS " +
        "to your selected third-party AdGuard DNS provider. That provider may see queried domains " +
        "and your connecting IP address under its own privacy policy. " +
        "Optional DNS diagnostics retain up to 64 events in RAM until stop or disable; session counters are temporary. " +
        "The filter can block ad/tracker domains used by other apps, though some traffic may bypass it. " +
        "Another VPN cannot operate simultaneously. You can stop Kanaf DNS at any time. " +
        "Do you explicitly agree to enable the local VPN and send DNS queries to the selected provider?"

    val PRIVACY_AR = "كنف: سياسة الخصوصية داخل التطبيق.\n\n" +
        "الفحص: تُقرأ الملفات التي تختارها وحزم التطبيقات المتاحة وفق صلاحيات أندرويد محليًا؛ " +
        "لا تُرفع الملفات أو محتوياتها إلى خوادم كنف. نتائج الجلسة المختصرة اختيارية وتُمسح عند الإيقاف.\n\n" +
        "DNS: لا يجمع كنف سجلًا بأسماء النطاقات. عند تفعيلك VPN الاختياري تُرسل طلبات DNS " +
        (if (BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY)
            "المسموح بها عبر HTTPS إلى Cloudflare DNS الأمني، الذي يحجب البرمجيات الخبيثة والتصيد وليس الإعلانات؛ "
         else "المسموح بها عبر HTTPS إلى مزوّد AdGuard DNS الخارجي الذي اخترته؛ ") +
        "قد يتلقى المزوّد أسماء النطاقات وعنوان IP ويطبّق سياسة الخصوصية الخاصة به.\n\n" +
        "التحديثات: عند اختيار تحديث قواعد الكشف، يتصل التطبيق بعنوان HTTPS المخصص للناشر " +
        "للتحقق من قواعد موقّعة. الخزنة تحتفظ بنسخ مشفرة داخل التطبيق باستخدام Android Keystore؛ " +
        "يمكنك حذفها يدويًا. تُزال بيانات التطبيق المحلية عند إلغاء التثبيت وفق نظام أندرويد.\n\n" +
        "التصاريح: عرض التطبيقات والوصول إلى الملفات المشتركة وVPN ميزات تتطلب موافقتك أو " +
        "أذونات أندرويد؛ لا يمكن قراءة البيانات الخاصة بالتطبيقات الأخرى.\n\n" +
        "الناشر: NabdhServ.Net. للاستفسارات عن الخصوصية استخدم قنوات التواصل على موقع الناشر. " +
        "تتطلب نسخة المتجر كذلك صفحة سياسة خصوصية عامة موثقة."

    val PRIVACY_EN = "Kanaf: in-app privacy policy.\n\n" +
        "Scanning: files you select and Android-visible installed packages are inspected locally " +
        "under Android permissions; file contents are not uploaded to Kanaf servers. " +
        "Optional brief session history is cleared when disabled.\n\n" +
        "DNS: DNS diagnostic history is optional, limited to 64 events in RAM, and cleared on stop or disable. Explicit local-rule exceptions are saved on device. When you enable optional VPN filtering, allowed " +
        (if (BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY)
            "queries are sent over HTTPS to Cloudflare security DNS for malware and phishing protection, not ad blocking. "
         else "queries are sent over HTTPS to your chosen independent AdGuard DNS provider. ") +
        "The provider may receive domain names and your connecting IP address, under its own privacy policy.\n\n" +
        "Updates: when you request threat-rule updates or enable daily signed updates, the app contacts the publisher-configured " +
        "HTTPS address for signed rules. The encrypted vault stores copies locally using Android " +
        "Keystore; you can remove them manually. Android deletes local app data on uninstall.\n\n" +
        "Permissions: app visibility, shared-file access and VPN are subject to user choices and " +
        "Android permissions. Private data belonging to other apps cannot be read.\n\n" +
        "Publisher: NabdhServ.Net. Contact the publisher through its website for privacy inquiries. " +
        "A verified publicly hosted privacy policy is also required before a Play release."
}
