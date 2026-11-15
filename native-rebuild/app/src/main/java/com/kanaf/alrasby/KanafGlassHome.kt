package com.kanaf.alrasby

import androidx.compose.foundation.clickable
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.kanaf.alrasby.engine.LinkInspector
import com.kanaf.alrasby.engine.EncryptedVault

private val Teal = Color(0xFF146C70)
private val Aqua = Color(0xFF3DDFB0)
private val Night = Color(0xFF0A1729)

@Composable
fun KanafGlassHome(
    busy: Boolean,
    sharedText: String?,
    scanHistory: List<String>,
    hasScanReport: Boolean,
    onShareReport: () -> Unit,
    vaultItems: List<EncryptedVault.Entry>,
    vaultStatus: String,
    onAddToVault: () -> Unit,
    onRestoreVault: (String) -> Unit,
    onDeleteVault: (String) -> Unit,
    keepSessionHistory: Boolean,
    onSessionHistoryChanged: (Boolean) -> Unit,
    onClearHistory: () -> Unit,
    status: String,
    selfTestStatus: String,
    onTestEngines: () -> Unit,
    onPickFile: () -> Unit,
    onOpenSystemApps: () -> Unit,
    onOpenWebsite: () -> Unit
) {
    var page by remember { mutableIntStateOf(if (sharedText.isNullOrBlank()) 0 else 1) }
    var linkInput by remember { mutableStateOf(sharedText.orEmpty()) }
    var linkReport by remember { mutableStateOf<LinkInspector.Report?>(null) }
    var confirmVaultSave by remember { mutableStateOf(false) }
    var deleteVaultId by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(sharedText) {
        if (!sharedText.isNullOrBlank()) {
            linkInput = sharedText
            linkReport = null
            page = 1
        }
    }
    val scrollState = rememberScrollState()
    LaunchedEffect(page) { scrollState.scrollTo(0) }
    val arabic = java.util.Locale.getDefault().language == "ar"
    fun tr(ar: String, en: String) = if (arabic) ar else en
    if (confirmVaultSave) {
        AlertDialog(
            onDismissRequest = { confirmVaultSave = false },
            title = { Text(tr("إضافة نسخة مشفرة", "Save encrypted copy")) },
            text = { Text(tr(
                "سيختار المستخدم ملفًا لنسخه إلى خزنة كنف المشفرة (16 ميجابايت كحد أقصى). الملف الأصلي لن يُحذف أو يُعزل عن التطبيقات الأخرى. لا تفتح ملفات غير موثوقة.",
                "Choose a file to copy into Kanaf's encrypted vault (up to 16 MiB). The original remains accessible to other apps: this is not automatic quarantine. Do not open untrusted files."
            )) },
            confirmButton = {
                TextButton(onClick = { confirmVaultSave = false; onAddToVault() }) {
                    Text(tr("اختيار ملف", "Choose file"))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmVaultSave = false }) {
                    Text(tr("إلغاء", "Cancel"))
                }
            }
        )
    }
    deleteVaultId?.let { selected ->
        AlertDialog(
            onDismissRequest = { deleteVaultId = null },
            title = { Text(tr("حذف النسخة المشفرة؟", "Delete encrypted copy?")) },
            text = { Text(tr(
                "سيُحذف الملف المشفر المخزن داخل كنف فقط. لا يمكن التراجع عن الحذف، ولن يتأثر الملف الأصلي.",
                "This permanently deletes only the copy stored in Kanaf. The original file remains unchanged."
            )) },
            confirmButton = {
                TextButton(onClick = { deleteVaultId = null; onDeleteVault(selected) }) {
                    Text(tr("حذف النسخة", "Delete copy"))
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteVaultId = null }) {
                    Text(tr("إلغاء", "Cancel"))
                }
            }
        )
    }
    fun signalText(signal: LinkInspector.Signal): String = when (signal) {
        LinkInspector.Signal.UNENCRYPTED_HTTP -> tr("اتصال HTTP غير مشفر", "Unencrypted HTTP connection")
        LinkInspector.Signal.USER_INFO -> tr("عنوان قد يخفي المضيف الحقيقي باستخدام @", "User-info (@) may disguise the real host")
        LinkInspector.Signal.IP_ADDRESS -> tr("رابط يستخدم عنوان IP مباشرة", "Direct IP address instead of a domain")
        LinkInspector.Signal.PUNYCODE -> tr("اسم نطاق دولي مشفر يحتاج للتحقق", "Encoded international domain needs verification")
        LinkInspector.Signal.NONSTANDARD_PORT -> tr("منفذ اتصال غير معتاد", "Nonstandard connection port")
        LinkInspector.Signal.LONG_URL -> tr("عنوان طويل بصورة غير اعتيادية", "Unusually long link")
        LinkInspector.Signal.INVALID_HOST -> tr("تعذر تحليل عنوان المضيف بثقة", "Unable to parse the host reliably")
    }
    val dark = isSystemInDarkTheme()
    val background = if (dark) Night else Color(0xFFF2F7F7)
    val ink = if (dark) Color(0xFFF0FBFA) else Night
    val secondary = if (dark) Color(0xFFB4CDCF) else Color(0xFF47666C)
    val card = if (dark) Color(0xFF1D3447).copy(alpha = 0.85f) else Color.White.copy(alpha = 0.84f)
    val stroke = if (dark) Aqua.copy(alpha = 0.24f) else Color.White.copy(alpha = 0.95f)

    MaterialTheme(colorScheme = if (dark) darkColorScheme(primary = Aqua, surface = Night, onSurface = ink)
        else lightColorScheme(primary = Teal, surface = background, onSurface = ink)) {
        Box(
            Modifier.fillMaxSize().background(
                Brush.verticalGradient(
                    if (dark) listOf(Night, Color(0xFF123C47), Night)
                    else listOf(Color(0xFFE2F5F0), background, Color(0xFFE8EEF8))
                )
            )
        ) {
            Column(
                Modifier.fillMaxSize().verticalScroll(scrollState)
                    .padding(horizontal = 20.dp, vertical = 28.dp),
                verticalArrangement = Arrangement.spacedBy(18.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("⬡", color = if (dark) Aqua else Teal, style = MaterialTheme.typography.headlineLarge)
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text("كنف", color = ink, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                        Text("KANAF · SECURITY STUDIO", color = secondary, style = MaterialTheme.typography.labelSmall)
                    }
                }
                Row(
                    Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(7.dp)
                ) {
                    listOf(
                        tr("الفحص", "Scan"),
                        tr("الروابط", "Links"),
                        tr("السجل", "History"),
                        tr("المحركات", "Engines"),
                        tr("حول كنف", "About"),
                        tr("الإعدادات", "Settings"),
                        tr("الخزنة", "Vault")
                    ).forEachIndexed { index, title ->
                        if (page == index) {
                            Button(
                                onClick = { page = index },
                                modifier = Modifier.widthIn(min = 86.dp),
                                shape = RoundedCornerShape(14.dp),
                                contentPadding = PaddingValues(horizontal = 4.dp, vertical = 9.dp)
                            ) { Text(title, style = MaterialTheme.typography.labelMedium) }
                        } else {
                            OutlinedButton(
                                onClick = { page = index },
                                modifier = Modifier.widthIn(min = 86.dp),
                                shape = RoundedCornerShape(14.dp),
                                contentPadding = PaddingValues(horizontal = 4.dp, vertical = 9.dp)
                            ) { Text(title, style = MaterialTheme.typography.labelMedium) }
                        }
                    }
                }
                if (page == 0) {
                GlassPanel(card, stroke) {
                    Text(tr("مركز الحماية", "Protection center"), color = secondary, style = MaterialTheme.typography.titleMedium)
                    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                        KanafShieldEmblem(busy = busy, dark = dark)
                    }
                    Spacer(Modifier.height(12.dp))
                    Text(
                        if (busy) tr("الفحص جارٍ…", "Scanning…") else tr("جاهز لفحص ملف", "Ready to scan a file"),
                        color = ink, style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        tr("خصوصيتك أولًا. يتم تحليل الملف محليًا دون رفعه أو حذفه.", "Privacy first. The selected file is analyzed locally without upload or deletion."),
                        color = secondary, style = MaterialTheme.typography.bodyMedium
                    )
                    Spacer(Modifier.height(20.dp))
                    Button(
                        onClick = onPickFile, enabled = !busy,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 54.dp),
                        shape = RoundedCornerShape(18.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (dark) Aqua else Teal,
                            contentColor = if (dark) Night else Color.White
                        )
                    ) {
                        Text(if (busy) tr("جارٍ الفحص…", "Scanning…") else tr("اختيار ملف للفحص", "Choose file to scan"), fontWeight = FontWeight.Bold)
                    }
                    if (busy) {
                        Spacer(Modifier.height(12.dp))
                        LinearProgressIndicator(Modifier.fillMaxWidth(), color = Aqua)
                    }
                }
                GlassPanel(card, stroke) {
                    Text(tr("نتيجة الفحص", "Scan result"), color = ink, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(12.dp))
                    Text(status, color = secondary, style = MaterialTheme.typography.bodyMedium)
                    if (hasScanReport) {
                        Spacer(Modifier.height(12.dp))
                        OutlinedButton(
                            onClick = onShareReport, enabled = !busy,
                            modifier = Modifier.fillMaxWidth()
                        ) { Text(tr("مشاركة التقرير باختياري", "Share report manually")) }
                        Text(tr(
                            "قد يتضمن التقرير بصمة SHA-256. لن تتم مشاركته إلا بعد اختيارك لتطبيق الاستلام.",
                            "The report may contain a SHA-256 fingerprint. Nothing is shared until you choose a recipient app."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                    }
                }
                GlassPanel(card, stroke) {
                    Text(tr("قدرات الفحص الحالية", "Current scanning capabilities"), color = ink, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(10.dp))
                    Text("SHA-256  •  ZIP  •  APK  •  DEX", color = if (dark) Aqua else Teal,
                        style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        tr("فحص بنية الملفات ومطابقة التوقيعات المحلية، مع اختبار ClamAV وYARA-X بقواعد EICAR المحدودة. عدم العثور على تطابق لا يثبت السلامة.", "Local SHA-256 and file structure checks; ClamAV and YARA-X test-rule scans recognize EICAR only. No match does not prove safety."),
                        color = secondary, style = MaterialTheme.typography.bodySmall
                    )
                }
                } // end scan page

                if (page == 1) {
                    GlassPanel(card, stroke) {
                        Text(tr("تحليل الروابط والنصوص", "Link and text inspection"),
                            color = ink, style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold)
                        Text(tr(
                            "ألصق رابطًا أو نصًا يحتوي على روابط، أو شاركه إلى كنف من تطبيق آخر.",
                            "Paste a link or message containing links, or share text to Kanaf from another app."
                        ), color = secondary, style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.height(12.dp))
                        OutlinedTextField(
                            value = linkInput,
                            onValueChange = {
                                linkInput = it.take(LinkInspector.MAX_TEXT_CHARS + 1)
                                linkReport = null
                            },
                            modifier = Modifier.fillMaxWidth().heightIn(min = 120.dp),
                            label = { Text(tr("الرابط أو النص", "Link or message text")) },
                            maxLines = 7
                        )
                        Spacer(Modifier.height(12.dp))
                        Button(
                            onClick = { linkReport = LinkInspector.inspectText(linkInput) },
                            enabled = linkInput.isNotBlank(),
                            modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
                            shape = RoundedCornerShape(16.dp)
                        ) {
                            Text(tr("تحليل محلي", "Inspect locally"))
                        }
                        Text(tr(
                            "تحليل بنيوي فقط لروابط HTTP/HTTPS، دون اتصال بالشبكة أو فتح الروابط. لا يتحقق من سمعة الموقع أو وجود برمجيات خبيثة.",
                            "Structure-only HTTP/HTTPS inspection. No network access or link opening. This does not check site reputation or malware."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                    }
                    linkReport?.let { report ->
                        GlassPanel(card, stroke) {
                            Text(tr("نتائج تحليل الروابط", "Link inspection results"),
                                color = ink, style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold)
                            if (report.truncated) {
                                Text(tr(
                                    "تم الوصول إلى حد النص أو عدد الروابط. النتائج جزئية ولا تشمل كل المحتوى.",
                                    "Text or link count limit reached. Results are partial."
                                ), color = secondary)
                            }
                            if (report.items.isEmpty()) {
                                Text(tr("لم يتم العثور على روابط HTTP/HTTPS قابلة للتحليل. لم يُفحص النص بحثًا عن تهديدات.",
                                    "No HTTP/HTTPS links were found. The text was not scanned for threats."),
                                    color = secondary)
                            }
                        }
                        report.items.forEach { item ->
                            GlassPanel(card, stroke) {
                                Text(item.host ?: tr("مضيف غير قابل للتحليل", "Unparseable host"),
                                    color = ink, style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.SemiBold)
                                Text(item.url.take(240) + if (item.url.length > 240) "…" else "",
                                    color = secondary, style = MaterialTheme.typography.bodySmall)
                                Spacer(Modifier.height(8.dp))
                                Text(when (item.verdict) {
                                    LinkInspector.Verdict.REVIEW ->
                                        tr("مؤشرات تستدعي التحقق؛ ليست إثباتًا على وجود خطر.",
                                            "Review these indicators; they do not prove maliciousness.")
                                    LinkInspector.Verdict.INVALID ->
                                        tr("تعذر تحليل الرابط بدقة؛ لا تعتبره موثوقًا.",
                                            "Could not parse this URL reliably; do not assume it is trustworthy.")
                                    LinkInspector.Verdict.NOT_VERIFIED ->
                                        tr("لم تظهر مؤشرات بنيوية معروفة؛ سلامة الرابط غير مؤكدة.",
                                            "No structural flags found; the link's safety is not verified.")
                                }, color = if (dark) Aqua else Teal)
                                item.signals.forEach { signal ->
                                    Text("• " + signalText(signal), color = secondary,
                                        style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                    }
                }

                if (page == 2) {
                    GlassPanel(card, stroke) {
                        Row(
                            Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(tr("سجل فحوصات الجلسة", "Session scan history"), color = ink,
                                style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                            TextButton(onClick = onClearHistory, enabled = scanHistory.isNotEmpty()) {
                                Text(tr("مسح", "Clear"))
                            }
                        }
                        Text(
                            if (keepSessionHistory) tr(
                                "آخر عشر نتائج مختصرة فقط، دون حفظ أسماء الملفات. يُمسح السجل عند إغلاق التطبيق.",
                                "Up to ten short results, without file names. History is cleared when the app closes."
                            ) else tr(
                                "سجل الجلسة معطل. لن تُحفظ نتائج الفحوصات التالية في السجل.",
                                "Session history is disabled. Future scan results will not be added to history."
                            ),
                            color = secondary, style = MaterialTheme.typography.bodySmall
                        )
                    }
                    if (scanHistory.isEmpty()) {
                        GlassPanel(card, stroke) {
                            Text(tr("لا توجد فحوصات في هذه الجلسة.", "No scans in this session."),
                                color = secondary)
                        }
                    } else {
                        scanHistory.forEachIndexed { index, summary ->
                            GlassPanel(card, stroke) {
                                Text(tr("الفحص", "Scan") + " " + (scanHistory.size - index),
                                    color = if (dark) Aqua else Teal,
                                    style = MaterialTheme.typography.labelLarge,
                                    fontWeight = FontWeight.SemiBold)
                                Spacer(Modifier.height(8.dp))
                                Text(summary, color = secondary, style = MaterialTheme.typography.bodyMedium)
                            }
                        }
                    }
                }
                if (page == 3) {
                    GlassPanel(card, stroke) {
                        Text(tr("محركات الكشف", "Detection engines"), color = ink,
                            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(10.dp))
                        Text("ClamAV 1.4.3", color = if (dark) Aqua else Teal,
                            style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Text(tr(
                            "مكتبة ARM64 أصلية. لا تُعتمد نتائجها حتى تنجح قواعد الاختبار والفحص الذاتي.",
                            "Native ARM64 library. Results are accepted only after rule verification and self-tests."
                        ), color = secondary)
                        Spacer(Modifier.height(16.dp))
                        Text("YARA-X 0.13.0", color = if (dark) Aqua else Teal,
                            style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Text(tr(
                            "محرك قواعد أصلي. الكشف الحالي محصور في توقيع EICAR التجريبي.",
                            "Native rule scanner. The current rule recognizes only the EICAR test pattern."
                        ), color = secondary)
                    }
                    GlassPanel(card, stroke) {
                        Text(tr("اختبار الكشف الفعلي", "Live detection self-test"), color = ink,
                            style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Spacer(Modifier.height(8.dp))
                        Text(tr(
                            "اختبر ClamAV وYARA-X باستخدام عينة EICAR الآمنة المدمجة، دون اختيار ملف أو الاتصال بالإنترنت.",
                            "Run the native ClamAV and YARA-X engines on the built-in harmless EICAR test sample, entirely offline."
                        ), color = secondary)
                        Spacer(Modifier.height(12.dp))
                        Button(
                            onClick = onTestEngines, enabled = !busy,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
                            shape = RoundedCornerShape(16.dp)
                        ) {
                            Text(if (busy) tr("جارٍ الاختبار…", "Testing…")
                                else tr("اختبار المحركين الآن", "Test both engines"))
                        }
                        if (selfTestStatus.isNotBlank()) {
                            Spacer(Modifier.height(12.dp))
                            Text(selfTestStatus, color = secondary,
                                style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                    GlassPanel(card, stroke) {
                        Text(tr("حدود الإصدار التجريبي", "Preview limitations"), color = ink,
                            style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Text(tr(
                            "الاختبارات على ملفات يختارها المستخدم فقط، وبحد 16 ميجابايت للمحركين. لا توجد قاعدة تهديدات شاملة أو حماية فورية أو فحص تلقائي للجهاز.",
                            "User-selected files only, maximum 16 MiB for native scanning. No comprehensive threat database, realtime protection, or automated device-wide scan."
                        ), color = secondary)
                    }
                }
                if (page == 4) {
                    GlassPanel(card, stroke) {
                        Text(tr("الخصوصية", "Privacy"), color = ink,
                            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        Text(tr(
                            "لا يتم رفع الملفات إلى خادم أو حذف الملف الأصلي. تُستخدم نسخة مؤقتة داخل مساحة التطبيق الخاصة أثناء الفحص ثم تُزال.",
                            "Files are not uploaded or deleted. A temporary copy is made in the app's private cache for scanning, then removed."
                        ), color = secondary)
                    }
                    GlassPanel(card, stroke) {
                        Text(tr("عن كنف", "About Kanaf"), color = ink,
                            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        Text(tr(
                            "كنف — استوديو الأمان. هذه نسخة اختبار تقني للمحركات، ولا تعادل حماية جهاز كاملة.",
                            "Kanaf Security Studio. This is a technical preview of the native engines, not complete device protection."
                        ), color = secondary)
                    }
                }
                if (page == 5) {
                    GlassPanel(card, stroke) {
                        Text(tr("إعدادات الخصوصية", "Privacy settings"), color = ink,
                            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(12.dp))
                        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween) {
                            Column(Modifier.weight(1f)) {
                                Text(tr("سجل فحوصات الجلسة", "Session scan history"),
                                    color = ink, style = MaterialTheme.typography.titleMedium)
                                Text(tr(
                                    "احتفظ بآخر عشر نتائج مختصرة في الذاكرة فقط. عند الإيقاف يُمسح السجل فورًا.",
                                    "Keep up to ten brief results in memory only. Turning this off clears the history immediately."
                                ), color = secondary, style = MaterialTheme.typography.bodySmall)
                            }
                            Spacer(Modifier.width(12.dp))
                            Switch(checked = keepSessionHistory, onCheckedChange = onSessionHistoryChanged)
                        }
                    }
                    GlassPanel(card, stroke) {
                        Text(tr("أذونات ونطاق الحماية", "Permissions and protection scope"),
                            color = ink, style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold)
                        Text(tr(
                            "يُفحص فقط الملف الذي تختاره. لا تُقرأ الرسائل أو التطبيقات الأخرى بصمت، ولا توجد حماية تلقائية في الخلفية أو تحديثات توقيعات عبر الشبكة.",
                            "Only files you choose are scanned. Messages and other apps are not silently inspected. Background protection and remote signature updates are not enabled."
                        ), color = secondary, style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.height(12.dp))
                        OutlinedButton(onClick = onOpenSystemApps,
                            modifier = Modifier.fillMaxWidth()) {
                            Text(tr("إدارة التطبيقات والأذونات عبر أندرويد",
                                "Manage apps and permissions in Android"))
                        }
                        Text(tr(
                            "يفتح إعدادات أندرويد الرسمية لتعديل الأذونات أو إيقاف تطبيق يدويًا؛ لا يقيّد كنف التطبيقات من تلقاء نفسه.",
                            "Opens Android system settings for manual permissions or app controls; Kanaf does not restrict other apps itself."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                    }
                }
                if (page == 6) {
                    GlassPanel(card, stroke) {
                        Text(tr("الخزنة المشفرة", "Encrypted vault"), color = ink,
                            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(8.dp))
                        Text(tr(
                            "تحتفظ كنف بنسخة مشفرة محليًا بمفتاح من Android Keystore. لا تتصل بالإنترنت ولا تحفظ أسماء الملفات. تبقى الملفات الأصلية في مكانها؛ ليست هذه ميزة حجر تلقائي.",
                            "Kanaf keeps an encrypted local copy using Android Keystore. No uploads or original filenames are stored. Original files are unchanged; this is not automatic quarantine."
                        ), color = secondary, style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.height(12.dp))
                        Button(onClick = { confirmVaultSave = true }, enabled = !busy,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp),
                            shape = RoundedCornerShape(16.dp)) {
                            Text(tr("إضافة ملف إلى الخزنة", "Add file to vault"))
                        }
                        Text(tr(
                            "ملفات حتى 16 ميجابايت. يؤدي مسح بيانات التطبيق أو فقدان مفتاح Keystore إلى تعذر استعادة النسخ المشفرة.",
                            "Files up to 16 MiB. Clearing app data or losing the Android Keystore key makes vault files unrecoverable."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                        if (vaultStatus.isNotBlank()) {
                            Spacer(Modifier.height(12.dp))
                            Text(vaultStatus, color = ink, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                    if (vaultItems.isEmpty()) {
                        GlassPanel(card, stroke) {
                            Text(tr("الخزنة فارغة حاليًا", "No encrypted copies yet"),
                                color = secondary)
                        }
                    } else vaultItems.forEachIndexed { index, entry ->
                        GlassPanel(card, stroke) {
                            Text(tr("نسخة مشفرة", "Encrypted copy") + " #${index + 1}",
                                color = ink, style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold)
                            Text(tr("المعرّف: ", "ID: ") + entry.id.take(8) +
                                " · " + (entry.storedBytes / 1024) + " KiB",
                                color = secondary, style = MaterialTheme.typography.bodySmall)
                            Text(java.text.DateFormat.getDateTimeInstance()
                                .format(java.util.Date(entry.savedAtMillis)),
                                color = secondary, style = MaterialTheme.typography.bodySmall)
                            Spacer(Modifier.height(8.dp))
                            Row(Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(onClick = { onRestoreVault(entry.id) },
                                    enabled = !busy,
                                    modifier = Modifier.weight(1f)) {
                                    Text(tr("استعادة إلى ملف", "Restore file"))
                                }
                                OutlinedButton(onClick = { deleteVaultId = entry.id },
                                    enabled = !busy,
                                    modifier = Modifier.weight(1f)) {
                                    Text(tr("حذف النسخة", "Delete copy"))
                                }
                            }
                        }
                    }
                }
                Text(
                    "Made with ❤️ By NabdhServ.Net",
                    modifier = Modifier.fillMaxWidth()
                        .border(1.dp, stroke, RoundedCornerShape(50))
                        .background(card, RoundedCornerShape(50))
                        .clickable(onClick = onOpenWebsite)
                        .padding(horizontal = 16.dp, vertical = 13.dp),
                    color = ink,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold,
                    textAlign = TextAlign.Center
                )
                Text(
                    tr("نسخة تطويرية · لا توفر حماية شاملة أو فحصًا تلقائيًا للجهاز", "Preview build · no comprehensive or automatic device protection"),
                    modifier = Modifier.fillMaxWidth(),
                    color = secondary, style = MaterialTheme.typography.labelSmall,
                    textAlign = TextAlign.Center
                )
            }
        }
    }
}

@Composable
private fun GlassPanel(
    fill: Color,
    outline: Color,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(
        Modifier.fillMaxWidth()
            .border(1.dp, outline, RoundedCornerShape(26.dp))
            .background(fill, RoundedCornerShape(26.dp))
            .padding(20.dp),
        content = content
    )
}
