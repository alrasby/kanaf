# Privacy / الخصوصية

Kanaf does not upload files, messages, links, or fingerprints.

The browser build downloads public signature databases only when asked (or from the copy shipped with the app). Quarantine uses AES-GCM with a non-exportable key kept in this browser. Message text is hashed and discarded. Logs keep counts, modes, and timestamps, not file paths beyond the name you already see in results.

## العربية

لا يرفع كنف ملفات ولا رسائل ولا روابط ولا بصمات. الاتصال الوحيد لتنزيل قواعد عامة، وعند الطلب. الحجر مشفّر بمفتاح غير قابل للتصدير داخل المتصفح. نص الرسالة لا يُحفظ.

## Play data disclosure (draft)

No data is sent to the developer. Signature databases are fetched from ClamAV mirrors and abuse.ch. If a store listing is filed later, the restricted permissions to declare are `QUERY_ALL_PACKAGES` (Android build only, not present in this browser build) and, only if the owner later enables inbox reading, `READ_SMS`. This build requests neither.
