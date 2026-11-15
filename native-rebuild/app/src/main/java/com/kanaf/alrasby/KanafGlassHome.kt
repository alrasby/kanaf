package com.kanaf.alrasby

import androidx.activity.compose.BackHandler
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
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import com.kanaf.alrasby.engine.LinkInspector
import com.kanaf.alrasby.engine.EncryptedVault
import com.kanaf.alrasby.engine.InstalledAppInventory

private val Teal = Color(0xFF146C70)
private val Aqua = Color(0xFF3DDFB0)
private val Night = Color(0xFF0A1729)

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun KanafGlassHome(
    busy: Boolean,
    sharedText: String?,
    uiLanguage: KanafLanguage,
    hiddenSections: Set<String>,
    onLanguageChange: (KanafLanguage) -> Unit,
    onSectionVisibilityChanged: (KanafSection, Boolean) -> Unit,
    scanHistory: List<String>,
    watchNewApps: Boolean,
    periodicChecks: Boolean,
    protectionStatus: String,
    onWatchNewApps: (Boolean) -> Unit,
    onChangePeriodic: (Boolean) -> Unit,
    onRunScopedCheck: () -> Unit,
    onRefreshProtection: () -> Unit,
    hasScanReport: Boolean,
    canImportSignedFeed: Boolean,
    signedFeedStatus: String,
    onImportSignedFeed: () -> Unit,
    onShareReport: () -> Unit,
    vaultItems: List<EncryptedVault.Entry>,
    vaultStatus: String,
    installedApps: List<InstalledAppInventory.Entry>,
    appsLoaded: Boolean,
    appsStatus: String,
    apkAuditStatus: String,
    onAuditApps: () -> Unit,
    onLoadApps: () -> Unit,
    onOpenAppDetails: (String) -> Unit,
    onAddToVault: () -> Unit,
    onQuarantineDocument: () -> Unit,
    onRestoreVault: (String) -> Unit,
    onDeleteVault: (String) -> Unit,
    keepSessionHistory: Boolean,
    onSessionHistoryChanged: (Boolean) -> Unit,
    onClearHistory: () -> Unit,
    status: String,
    selfTestStatus: String,
    onTestEngines: () -> Unit,
    onPickFile: () -> Unit,
    deviceScanStatus: String,
    onDeviceScan: () -> Unit,
    onScanChosenFolder: () -> Unit,
    onStopDeviceScan: () -> Unit,
    autoScanProgress: String,
    sharedStorageAccess: Boolean,
    scanAccessStatus: String,
    onRequestSharedStorage: () -> Unit,
    rulesUpdateStatus: String,
    onUpdateThreatRules: () -> Unit,
    vpnRequested: Boolean,
    vpnStatus: String,
    onVpnToggle: (Boolean) -> Unit,
    onVpnRefresh: () -> Unit,
    privateDnsStatus: String,
    privateDnsAvailable: Boolean,
    privateDnsCompatible: Boolean,
    privateDnsCanAutoSwitch: Boolean,
    privateDnsActionStatus: String,
    onCopyDnsGrant: () -> Unit,
    onOpenPrivateDnsSettings: () -> Unit,
    onChoosePrivateDns: (String?) -> Unit,
    onOpenSystemApps: () -> Unit,
    onOpenWebsite: () -> Unit
) {
    var page by remember { mutableIntStateOf(if (sharedText.isNullOrBlank()) 0 else 1) }
    // Android Back returns to the main screen instead of exiting from a subpage.
    BackHandler(enabled = page != 0) { page = 0 }
    var linkInput by remember { mutableStateOf(sharedText.orEmpty()) }
    var linkReport by remember { mutableStateOf<LinkInspector.Report?>(null) }
    var confirmVaultSave by remember { mutableStateOf(false) }
    var confirmQuarantine by remember { mutableStateOf(false) }
    var confirmVpn by remember { mutableStateOf(false) }
    var customPrivateDns by rememberSaveable { mutableStateOf("") }
    var sectionsOpen by rememberSaveable { mutableStateOf(false) }
    var detailsOpen by rememberSaveable { mutableStateOf(false) }
    var dnsAdvanced by rememberSaveable { mutableStateOf(false) }
    var deleteVaultId by remember { mutableStateOf<String?>(null) }
    var appSearch by remember { mutableStateOf("") }
    LaunchedEffect(sharedText) {
        if (!sharedText.isNullOrBlank()) {
            linkInput = sharedText
            linkReport = null
            page = 1
        }
    }
    val scrollState = rememberScrollState()
    LaunchedEffect(page) { scrollState.scrollTo(0) }
    val arabic = uiLanguage.isArabic()
    fun tr(ar: String, en: String) = if (arabic) ar else en
    if (confirmQuarantine) {
        AlertDialog(
            onDismissRequest = { confirmQuarantine = false },
            title = { Text(tr("حجر مستند مختار", "Quarantine a selected document")) },
            text = { Text(tr(
                "تنبيه: بعد حفظ نسخة مشفرة والتحقق منها، سيحاول كنف حذف المستند الأصلي من موفّر أندرويد إذا سمح بذلك. قد يصبح الوصول إلى الملف متعذرًا إلا من الخزنة، وفقدان مفتاح الجهاز يجعل استعادته مستحيلة. لا يمكن حجر ملفات التطبيقات الأخرى أو النظام بهذه الطريقة. هل توافق؟",
                "Warning: after storing and verifying an encrypted copy, Kanaf will ask Android's document provider to DELETE the selected original if allowed. Losing the device key can make recovery impossible. This does not isolate other apps or system files. Continue?"
            )) },
            confirmButton = {
                TextButton(onClick = { confirmQuarantine = false; onQuarantineDocument() }) {
                    Text(tr("أوافق وأختار المستند", "Agree and choose document"))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmQuarantine = false }) {
                    Text(tr("إلغاء", "Cancel"))
                }
            }
        )
    }
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
    if (confirmVpn) {
        AlertDialog(
            onDismissRequest = { confirmVpn = false },
            title = { Text(tr("تفعيل مرشح إعلانات DNS", "Enable DNS ad filter")) },
            text = { Text(tr(
                "يتطلب أندرويد موافقة VPN. عند توفر إذن ADB الاختياري سيضبط كنف Private DNS على «إيقاف» أثناء تشغيله، ثم «تلقائي» عند تعطيله؛ أي مزود سابق لن يُستعاد تلقائيًا. لا يمكنه العمل مع VPN آخر. هل توافق؟",
                "Android VPN permission is required. With the optional ADB grant, Kanaf switches system Private DNS Off while active and back to Automatic on stop; an old custom provider will not be automatically restored. It cannot share another VPN. Continue?"
            )) },
            confirmButton = {
                TextButton(onClick = { confirmVpn = false; onVpnToggle(true) }) {
                    Text(tr("المتابعة", "Continue"))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmVpn = false }) { Text(tr("إلغاء", "Cancel")) }
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
        LinkInspector.Signal.AD_TRACKER -> tr("نطاق إعلانات أو تتبع معروف، وليس دليلًا على برمجية خبيثة", "Known ad/tracker host; not proof of malware")
    }
    val dark = isSystemInDarkTheme()
    val background = if (dark) Night else Color(0xFFF2F7F7)
    val ink = if (dark) Color(0xFFF0FBFA) else Night
    val secondary = if (dark) Color(0xFFB4CDCF) else Color(0xFF47666C)
    val card = if (dark) Color(0xFF1D3447).copy(alpha = 0.85f) else Color.White.copy(alpha = 0.84f)
    val stroke = if (dark) Aqua.copy(alpha = 0.24f) else Color.White.copy(alpha = 0.95f)

    CompositionLocalProvider(LocalLayoutDirection provides if (arabic) LayoutDirection.Rtl else LayoutDirection.Ltr) {
    MaterialTheme(colorScheme = if (dark) darkColorScheme(primary = Aqua, surface = Night, onSurface = ink)
        else lightColorScheme(primary = Teal, surface = background, onSurface = ink)) {
        Box(
            Modifier.fillMaxSize().background(
                Brush.verticalGradient(
                    if (dark) listOf(Night, Color(0xFF123C47), Night)
                    else listOf(Color(0xFFE2F5F0), background, Color(0xFFE8EEF8))
                )
            ),
            contentAlignment = Alignment.TopCenter
        ) {
            Column(
                Modifier.widthIn(max = 680.dp).fillMaxWidth().fillMaxHeight()
                    .padding(horizontal = 16.dp, vertical = 18.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text("⬡", color = if (dark) Aqua else Teal,
                        style = MaterialTheme.typography.headlineLarge)
                    Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text(tr("كنف", "Kanaf"), color = ink,
                            style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                        Text(tr("مركز الأمان والخصوصية", "Security & privacy studio"),
                            color = secondary, style = MaterialTheme.typography.labelSmall)
                    }
                    OutlinedButton(
                        onClick = { page = if (page == 5) 0 else 5 },
                        modifier = Modifier.testTag("settings_button"),
                        shape = RoundedCornerShape(16.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            containerColor = if (page == 5) Teal.copy(alpha = 0.14f) else card,
                            contentColor = if (dark) Aqua else Teal
                        ),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                    ) {
                        Text(if (page == 5) "⌂" else "⚙",
                            style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.width(5.dp))
                        Text(if (page == 5) tr("الرئيسية", "Home")
                            else tr("الإعدادات", "Settings"),
                            style = MaterialTheme.typography.labelMedium)
                    }
                }
                if ((page != 0 && page != 5 && page != 9 && page != 10) ||
                    (page == 0 && sectionsOpen)) {
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(3.dp)
                    ) {
                        KanafSection.entries.filter { it.id !in hiddenSections }
                            .forEach { section ->
                                val label = when (section) {
                                    KanafSection.SCAN -> tr("الفحص", "Scan")
                                    KanafSection.LINKS -> tr("الروابط", "Links")
                                    KanafSection.APPS -> tr("التطبيقات", "Apps")
                                    KanafSection.VAULT -> tr("الخزنة", "Vault")
                                    KanafSection.PROTECTION -> tr("الحماية", "Protection")
                                    KanafSection.HISTORY -> tr("السجل", "History")
                                    KanafSection.ENGINES -> tr("المحركات", "Engines")
                                }
                                FilterChip(
                                    selected = page == section.page,
                                    onClick = { page = section.page },
                                    modifier = Modifier.testTag("nav_" + section.id)
                                        .heightIn(min = 48.dp),
                                    label = {
                                        Text(label, style = MaterialTheme.typography.labelMedium,
                                            fontWeight = if (page == section.page)
                                                FontWeight.Bold else FontWeight.Medium)
                                    },
                                    shape = RoundedCornerShape(15.dp),
                                    colors = FilterChipDefaults.filterChipColors(
                                        selectedContainerColor = if (dark) Color(0xFF185F65) else Teal,
                                        selectedLabelColor = Color.White
                                    ),
                                )
                            }
                    }
                }
                // Keep header and navigation reachable while lengthy cards scroll.
                Column(
                    Modifier.fillMaxWidth().weight(1f)
                        .verticalScroll(scrollState)
                        .padding(bottom = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                if (page == 0) {
                    GlassPanel(card, stroke) {
                        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                            KanafShieldEmblem(busy = busy, dark = dark)
                        }
                        Text(
                            if (busy) tr("جارٍ فحص جهازك", "Scanning your device")
                            else tr("كنف يحمي خصوصيتك", "Kanaf protects your privacy"),
                            color = ink, style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center
                        )
                        Text(tr(
                            "افحص التطبيقات والملفات المتاحة بضغطة واحدة. لا اختيار ملفات ولا حذف تلقائي.",
                            "One-tap inspection of installed apps and accessible files. No picker or automatic deletion."
                        ), color = secondary, style = MaterialTheme.typography.bodyMedium,
                            textAlign = TextAlign.Center)
                        Spacer(Modifier.height(14.dp))
                        Button(onClick = onDeviceScan, enabled = !busy,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 60.dp)
                                .testTag("device_scan_button"),
                            shape = RoundedCornerShape(20.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (dark) Aqua else Teal,
                                contentColor = if (dark) Night else Color.White
                            )
                        ) {
                            Text(if (busy) tr("جارٍ الفحص…", "Scanning…")
                                else tr("فحص الجهاز الآن", "Scan device now"),
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold)
                        }
                        if (busy) {
                            Spacer(Modifier.height(8.dp))
                            LinearProgressIndicator(Modifier.fillMaxWidth(), color = Aqua)
                            if (autoScanProgress.isNotBlank()) {
                                Text(autoScanProgress, color = secondary,
                                    style = MaterialTheme.typography.bodySmall)
                            }
                            TextButton(onClick = onStopDeviceScan,
                                modifier = Modifier.fillMaxWidth()
                                    .testTag("stop_device_scan")) {
                                Text(tr("إيقاف الفحص", "Stop scan"))
                            }
                        }
                        Text(
                            if (sharedStorageAccess)
                                tr("إذن الملفات المشتركة متاح", "Shared-files permission available")
                            else tr("فحص التطبيقات متاح؛ إذن الملفات يوسّع نطاق الفحص.",
                                "App scanning is available; files permission expands coverage."),
                            color = secondary, style = MaterialTheme.typography.bodySmall
                        )
                    }
                    if (deviceScanStatus.isNotBlank()) {
                        GlassPanel(card, stroke) {
                            Text(tr("نتيجة الفحص", "Scan result"),
                                color = ink, fontWeight = FontWeight.Bold,
                                style = MaterialTheme.typography.titleMedium)
                            Text(deviceScanStatus, color = secondary,
                                maxLines = if (detailsOpen) Int.MAX_VALUE else 5,
                                style = MaterialTheme.typography.bodySmall)
                            TextButton(onClick = { detailsOpen = !detailsOpen },
                                modifier = Modifier.fillMaxWidth()
                                    .testTag("scan_report_details")) {
                                Text(if (detailsOpen) tr("إخفاء التفاصيل", "Hide details")
                                    else tr("عرض التقرير", "View report"))
                            }
                        }
                    }
                    Row(Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        OutlinedButton(onClick = { page = 9 },
                            modifier = Modifier.weight(1f).heightIn(min = 56.dp)
                                .testTag("open_dns_page"),
                            shape = RoundedCornerShape(18.dp)) {
                            Text(tr("DNS وحجب الإعلانات", "DNS & ad blocking"),
                                maxLines = 2, textAlign = TextAlign.Center)
                        }
                        OutlinedButton(onClick = { page = 10 },
                            modifier = Modifier.weight(1f).heightIn(min = 56.dp)
                                .testTag("open_scan_tools"),
                            shape = RoundedCornerShape(18.dp)) {
                            Text(tr("خيارات الفحص", "Scan options"),
                                maxLines = 2, textAlign = TextAlign.Center)
                        }
                    }
                    GlassPanel(card, stroke) {
                        Text(tr("محركات الفحص", "Detection engines"), color = ink,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold)
                        Text("ClamAV 1.4.6   •   YARA-X 0.13.0",
                            color = if (dark) Aqua else Teal)
                        Text(tr(
                            "قواعد التهديدات الحالية اختبارية فقط؛ عدم العثور على تطابق لا يعني أن الجهاز خالٍ من الفيروسات.",
                            "Threat rules remain test-only; no match does not mean the device is malware-free."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                    }
                    TextButton(onClick = { sectionsOpen = !sectionsOpen },
                        modifier = Modifier.fillMaxWidth().testTag("more_features")) {
                        Text(if (sectionsOpen) tr("إخفاء الأقسام", "Hide sections")
                            else tr("المزيد من ميزات كنف", "More Kanaf features"))
                    }
                }
                if (page == 9) {
                    GlassPanel(card, stroke) {
                        Text(tr("إعدادات DNS", "DNS settings"), color = ink,
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold)
                        Text(tr(
                            "هذه الإعدادات مستقلة عن فحص الفيروسات. يمكنك استخدام DNS الخاص في الهاتف أو VPN كنف المحلي، وليس كليهما في الوقت نفسه.",
                            "DNS controls are separate from antivirus scanning. Choose Android Private DNS or Kanaf local VPN, not both simultaneously."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                    }
                if (privateDnsAvailable) GlassPanel(card, stroke) {
                    Text(tr("Private DNS للنظام", "Android Private DNS"),
                        color = ink, style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold)
                    Text(privateDnsStatus, color = if (dark) Aqua else Teal,
                        style = MaterialTheme.typography.bodyMedium)
                    Text(tr(
                        "الأوضاع التالية اختصارات لإعدادات Android فقط؛ لا يمكن لتطبيق عادي تغيير Private DNS تلقائيًا. مزوّدو DNS يحجبون الإعلانات بحسب سياسة كل مزوّد، وليس بمحرك كنف المحلي.",
                        "These controls open Android Settings only; ordinary apps cannot change Private DNS automatically. Provider-side filtering depends on each provider's policy, not Kanaf's local engine."
                    ), color = secondary, style = MaterialTheme.typography.bodySmall)
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        OutlinedButton(onClick = { onChoosePrivateDns(null) },
                            modifier = Modifier.testTag("dns_system_off")) {
                            Text(tr("DNS متوقف", "DNS Off"))
                        }
                        OutlinedButton(onClick = { onChoosePrivateDns(null) },
                            modifier = Modifier.testTag("dns_system_auto")) {
                            Text(tr("DNS تلقائي", "DNS Auto"))
                        }
                    }
                    for (host in listOf(
                        "dns.adguard.com", "dns.adguard-dns.com", "family.adguard-dns.com"
                    )) {
                        OutlinedButton(onClick = { onChoosePrivateDns(host) },
                            modifier = Modifier.fillMaxWidth()) {
                            Text(host, maxLines = 2)
                        }
                    }
                    OutlinedTextField(
                        value = customPrivateDns,
                        onValueChange = { customPrivateDns = it.take(253) },
                        modifier = Modifier.fillMaxWidth().testTag("dns_custom_provider"),
                        label = { Text(tr("مزود DNS خاص", "Custom DNS provider")) },
                        singleLine = true
                    )
                    OutlinedButton(onClick = { onChoosePrivateDns(customPrivateDns.trim()) },
                        enabled = customPrivateDns.isNotBlank(),
                        modifier = Modifier.fillMaxWidth().testTag("dns_add_provider")) {
                        Text(tr("نسخ المزود وفتح إعدادات Android", "Copy provider and open Android Settings"))
                    }
                    TextButton(onClick = onOpenPrivateDnsSettings,
                        modifier = Modifier.fillMaxWidth().testTag("open_android_private_dns")) {
                        Text(tr("فتح إعدادات DNS في الهاتف", "Open phone DNS settings"))
                    }
                    Text(tr(
                        "للوصول السريع: أضف مربع Kanaf DNS من تحرير لوحة الإعدادات السريعة. إذا كان Private DNS تلقائيًا أو بمزوّد، فلن يشغل كنف VPN المحلي.",
                        "Add the Kanaf DNS tile from Android Quick Settings edit. With Private DNS Automatic or a provider configured, Kanaf's local VPN stays disabled."
                    ), color = secondary, style = MaterialTheme.typography.bodySmall)
                    if (privateDnsActionStatus.isNotBlank()) {
                        Text(privateDnsActionStatus, color = secondary,
                            style = MaterialTheme.typography.bodySmall)
                    }
                }
                GlassPanel(card, stroke) {
                    Text(tr("كاشف الإعلانات ومرشح DNS", "Ad and tracker DNS filter"),
                        color = ink, style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold)
                    Text(tr(
                        "مرشح VPN محلي اختياري يحجب بعض نطاقات الإعلانات. للمستخدم العادي: اضبط DNS الخاص في الهاتف على «إيقاف» أولًا، دون الحاجة إلى ADB.",
                        "Optional local VPN blocks a limited list of ad domains. No ADB needed: turn Android Private DNS Off in system settings first."
                    ), color = secondary, style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(8.dp))
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text(tr("طلب تفعيل حجب DNS", "Request DNS filtering"),
                            modifier = Modifier.weight(1f), color = ink)
                        Switch(checked = vpnRequested,
                            enabled = vpnRequested || privateDnsCompatible || privateDnsCanAutoSwitch,
                            onCheckedChange = { enabled ->
                                if (enabled) confirmVpn = true else onVpnToggle(false)
                            },
                            modifier = Modifier.testTag("dns_filter_switch"))
                    }
                    if (!privateDnsCompatible && !privateDnsCanAutoSwitch && !vpnRequested) {
                        Text(tr(
                            "لفتح مرشح كنف اختر «DNS متوقف» من إعدادات الهاتف أولًا. لا تحتاج إعدادات المطور.",
                            "To enable Kanaf's filter, select Private DNS Off in phone settings. Developer tools are not needed."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                    }
                    TextButton(
                        onClick = { dnsAdvanced = !dnsAdvanced },
                        modifier = Modifier.fillMaxWidth().testTag("dns_advanced_options")
                    ) {
                        Text(tr("خيارات متقدمة اختيارية", "Optional advanced options"))
                    }
                    if (dnsAdvanced) {
                    if (privateDnsAvailable) {
                        Text(
                            if (privateDnsCanAutoSwitch)
                                tr("تبديل DNS التلقائي متاح بإذن ADB", "Automatic DNS switching enabled by ADB")
                            else tr("إذن التبديل التلقائي غير مُنح", "Automatic switching permission not granted"),
                            color = secondary, style = MaterialTheme.typography.bodySmall
                        )
                        if (!privateDnsCanAutoSwitch) {
                            OutlinedButton(
                                onClick = onCopyDnsGrant,
                                modifier = Modifier.fillMaxWidth().testTag("copy_dns_adb_grant")
                            ) {
                                Text(tr("نسخ أمر منح الصلاحية عبر ADB", "Copy optional ADB grant command"))
                            }
                        }
                    }
                    }
                    OutlinedButton(onClick = onVpnRefresh, modifier = Modifier.fillMaxWidth()) {
                        Text(tr("التحقق من حالة المرشح", "Refresh filter status"))
                    }
                    if (vpnStatus.isNotBlank())
                        Text(vpnStatus, color = secondary, style = MaterialTheme.typography.bodySmall)
                }
                }
                if (page == 10) {
                    GlassPanel(card, stroke) {
                        Text(tr("خيارات الفحص والأذونات", "Scan options & permissions"),
                            color = ink, style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold)
                        Text(tr(
                            "فحص التطبيقات يبدأ من الرئيسية دون اختيار أي ملف. إذن الملفات المشتركة مطلوب مرة واحدة فقط لتوسيع النطاق؛ ولا يتيح قراءة بيانات التطبيقات الخاصة.",
                            "Installed-app scanning starts from Home without a file picker. One-time shared-files permission expands coverage but cannot access private app data."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                        OutlinedButton(onClick = onRequestSharedStorage,
                            modifier = Modifier.fillMaxWidth()
                                .testTag("request_storage_scan_access")) {
                            Text(if (sharedStorageAccess)
                                tr("إدارة إذن الملفات المشتركة", "Manage shared-files permission")
                                else tr("السماح بفحص الملفات المشتركة", "Allow shared-files access"))
                        }
                        if (scanAccessStatus.isNotBlank()) {
                            Text(scanAccessStatus, color = secondary,
                                style = MaterialTheme.typography.bodySmall)
                        }
                        OutlinedButton(onClick = onPickFile, enabled = !busy,
                            modifier = Modifier.fillMaxWidth().testTag("manual_file_scan")) {
                            Text(tr("فحص ملف منفرد", "Scan individual file"))
                        }
                        OutlinedButton(onClick = onScanChosenFolder, enabled = !busy,
                            modifier = Modifier.fillMaxWidth().testTag("manual_folder_scan")) {
                            Text(tr("فحص مجلد محدد", "Scan selected folder"))
                        }
                        OutlinedButton(onClick = onTestEngines, enabled = !busy,
                            modifier = Modifier.fillMaxWidth()
                                .testTag("home_native_engines_test")) {
                            Text(tr("اختبار محركي ClamAV وYARA-X", "Self-test ClamAV and YARA-X"))
                        }
                        if (selfTestStatus.isNotBlank()) {
                            Text(selfTestStatus, color = secondary,
                                style = MaterialTheme.typography.bodySmall)
                        }
                        if (status.isNotBlank()) {
                            Text(status, color = secondary,
                                style = MaterialTheme.typography.bodySmall)
                        }
                        if (hasScanReport) {
                            TextButton(onClick = onShareReport, enabled = !busy) {
                                Text(tr("مشاركة التقرير اختياريًا", "Share report manually"))
                            }
                        }
                    }
                }

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
                        Text("ClamAV 1.4.6", color = if (dark) Aqua else Teal,
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
                if (page == 3) {
                    GlassPanel(card, stroke) {
                        Text(tr("قواعد التهديدات الموقعة", "Authenticated threat database"), color = ink,
                            style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Text(tr(
                            "استيراد قاعدة بصمات SHA-256 من حزمة موقعة بواسطة مفتاح الإنتاج المثبت داخل التطبيق. لا يمكن الوثوق بمفتاح أو قاعدة يأتيان من مصدر غير مُعتمد.",
                            "Import an offline SHA-256 database only if its RSA signature verifies against the production key pinned inside Kanaf. An untrusted source cannot supply its own key."
                        ), color = secondary, style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.height(12.dp))
                        OutlinedButton(onClick = onImportSignedFeed,
                            enabled = canImportSignedFeed && !busy,
                            modifier = Modifier.fillMaxWidth()) {
                            Text(tr("استيراد قاعدة موقعة", "Import signed database"))
                        }
                        if (!canImportSignedFeed) {
                            Text(tr(
                                "غير مفعّل: لم يُثبّت مفتاح توقيع إنتاجي موثوق في البناء. القواعد الحالية اختبارية.",
                                "Disabled: no trusted production signing key is embedded in this build. Current signatures remain test-only."
                            ), color = secondary, style = MaterialTheme.typography.bodySmall)
                        }
                        if (signedFeedStatus.isNotBlank()) {
                            Text(signedFeedStatus, color = secondary, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
                if (page == 5) {
                    GlassPanel(card, stroke) {
                        Text(tr("اللغة والعرض", "Language & display"), color = ink,
                            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        Text(tr(
                            "تتغير لغة الواجهة واتجاهها فورًا دون إعادة تشغيل. تتوفر العربية والإنجليزية حاليًا؛ اللغات الأخرى تتبع الإنجليزية مؤقتًا حتى تكتمل ترجمتها.",
                            "Language and layout direction change immediately without a restart. Arabic and English are currently available; other system languages use English until translated."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                        Spacer(Modifier.height(10.dp))
                        listOf(KanafLanguage.SYSTEM, KanafLanguage.ARABIC, KanafLanguage.ENGLISH)
                            .forEach { option ->
                                val label = when (option) {
                                    KanafLanguage.SYSTEM -> tr("اتّباع لغة النظام", "Follow system language")
                                    KanafLanguage.ARABIC -> tr("العربية", "Arabic")
                                    KanafLanguage.ENGLISH -> tr("الإنجليزية", "English")
                                }
                                val detail = when (option) {
                                    KanafLanguage.SYSTEM -> tr("تلقائي حسب إعدادات جهازك", "Automatic, based on device settings")
                                    KanafLanguage.ARABIC -> tr("واجهة عربية واتجاه من اليمين إلى اليسار", "Arabic with right-to-left layout")
                                    KanafLanguage.ENGLISH -> tr("واجهة إنجليزية واتجاه من اليسار إلى اليمين", "English with left-to-right layout")
                                }
                                Row(
                                    Modifier.fillMaxWidth().clickable { onLanguageChange(option) }
                                        .heightIn(min = 56.dp).padding(vertical = 6.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    RadioButton(selected = uiLanguage == option,
                                        modifier = Modifier.testTag("lang_" + option.storedValue),
                                        onClick = { onLanguageChange(option) })
                                    Spacer(Modifier.width(8.dp))
                                    Column(Modifier.weight(1f)) {
                                        Text(label, color = ink, style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.SemiBold)
                                        Text(detail, color = secondary,
                                            style = MaterialTheme.typography.bodySmall)
                                    }
                                }
                            }
                    }
                    GlassPanel(card, stroke) {
                        Text(tr("تخصيص الأقسام العلوية", "Customize top sections"), color = ink,
                            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        Text(tr(
                            "أظهر أو أخفِ الأقسام غير الضرورية لك لتبقى الواجهة بسيطة. الإخفاء لا يعطل الميزة ولا يمسح بياناتها. يظل الفحص وزر الإعدادات متاحين دائمًا.",
                            "Show or hide optional sections to simplify navigation. Hiding a section does not disable its feature or delete data. Scan and Settings always remain accessible."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                        Spacer(Modifier.height(8.dp))
                        KanafSection.OPTIONAL.forEach { section ->
                            val label = when (section) {
                                KanafSection.LINKS -> tr("تحليل الروابط", "Link inspection")
                                KanafSection.APPS -> tr("مراجعة التطبيقات", "App review")
                                KanafSection.VAULT -> tr("الخزنة المشفرة", "Encrypted vault")
                                KanafSection.PROTECTION -> tr("الحماية والمراقبة", "Protection & monitoring")
                                KanafSection.HISTORY -> tr("سجل الجلسة", "Session history")
                                KanafSection.ENGINES -> tr("محركات الكشف", "Detection engines")
                                KanafSection.SCAN -> tr("الفحص", "Scan")
                            }
                            Row(Modifier.fillMaxWidth().heightIn(min = 50.dp),
                                verticalAlignment = Alignment.CenterVertically) {
                                Text(label, color = ink, style = MaterialTheme.typography.bodyMedium,
                                    modifier = Modifier.weight(1f))
                                Spacer(Modifier.width(12.dp))
                                Switch(
                                    modifier = Modifier.testTag("nav_switch_" + section.id),
                                    checked = section.id !in hiddenSections,
                                    onCheckedChange = { enabled ->
                                        onSectionVisibilityChanged(section, enabled)
                                    }
                                )
                            }
                        }
                    }
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
                                    "الاحتفاظ بآخر عشر نتائج مختصرة في الذاكرة فقط، دون أسماء الملفات. إيقاف هذا الخيار يمسح السجل فورًا.",
                                    "Store up to ten brief scan results in memory, without file names. Disabling this option clears the session history immediately."
                                ), color = secondary, style = MaterialTheme.typography.bodySmall)
                            }
                            Spacer(Modifier.width(12.dp))
                            Switch(checked = keepSessionHistory, onCheckedChange = onSessionHistoryChanged)
                        }
                    }
                    GlassPanel(card, stroke) {
                        Text(tr("أذونات ونطاق الحماية", "Permissions & protection scope"),
                            color = ink, style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold)
                        Text(tr(
                            "يفحص كنف حزم التطبيقات بطلب المستخدم دون اختيار ملف، ويمكنه فحص الملفات المشتركة بعد إذن أندرويد. لا يستطيع قراءة بيانات التطبيقات الخاصة أو ملفات النظام.",
                            "Kanaf scans installed APKs on request without a file picker. It inspects shared files with Android's special access, but cannot read private app data or protected system files."
                        ), color = secondary, style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.height(12.dp))
                        OutlinedButton(onClick = onOpenSystemApps,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                            Text(tr("إدارة التطبيقات والأذونات عبر أندرويد",
                                "Manage apps & permissions in Android"))
                        }
                        Text(tr(
                            "يفتح إعدادات أندرويد الرسمية لإدارة الأذونات يدويًا. لا يغيّر كنف أذونات التطبيقات الأخرى.",
                            "Opens official Android settings for manual controls. Kanaf does not modify other apps' permissions."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                    }
                    GlassPanel(card, stroke) {
                        Text(tr("تحديث قواعد ومحركات الكشف", "Threat rules & engine updates"),
                            color = ink, style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold)
                        Text(tr(
                            "يتحقق كنف من قاعدة تهديدات موقعة من الناشر. تحديث ملفات المحركات الأصلية يتطلب تحديث التطبيق نفسه.",
                            "Kanaf checks a publisher-signed threat database. Native engine binaries update through application releases."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                        OutlinedButton(onClick = onUpdateThreatRules, enabled = !busy,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp)
                                .testTag("update_detection_rules")) {
                            Text(tr("التحقق من تحديثات الكشف", "Check detection updates"))
                        }
                        if (rulesUpdateStatus.isNotBlank()) {
                            Text(rulesUpdateStatus, color = secondary,
                                style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    GlassPanel(card, stroke) {
                        Text(tr("حول كنف", "About Kanaf"), color = ink,
                            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        Text(tr(
                            "كنف — استوديو الأمان والخصوصية. يقدّم فحصًا محليًا وتحليل روابط ومراجعة تطبيقات وخزنة مشفرة. هذه نسخة تطويرية؛ لا تضمن خلو الجهاز من البرمجيات الخبيثة.",
                            "Kanaf Security & Privacy Studio provides local file and link inspection, app review and an encrypted vault. This is a development build; it does not certify a device is malware-free."
                        ), color = secondary, style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.height(8.dp))
                        Text(tr(
                            "لا تُرفع ملفات الفحص لخوادم. تُخزن اختيارات الواجهة داخل الجهاز. يبقى الحجر اليدوي وحذف الأصل متاحين فقط عند اختيارك وموافقتك الصريحة.",
                            "Selected files are not uploaded. Presentation settings stay on-device. Manual document quarantine and original deletion require your explicit selection and consent."
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
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(onClick = { confirmQuarantine = true }, enabled = !busy,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp),
                            shape = RoundedCornerShape(16.dp)) {
                            Text(tr("حجر مستند مختار (قد يحذف الأصل)",
                                "Quarantine selected document (may delete original)"))
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
                            Text(java.text.DateFormat.getDateTimeInstance(
                                java.text.DateFormat.MEDIUM,
                                java.text.DateFormat.SHORT,
                                uiLanguage.resolvedLocale()
                            ).format(java.util.Date(entry.savedAtMillis)),
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
                if (page == 7) {
                    GlassPanel(card, stroke) {
                        Text(tr("مراجعة التطبيقات", "App review"), color = ink,
                            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        Text(tr(
                            "يعرض كنف التطبيقات القابلة للتشغيل التي يسمح أندرويد برؤيتها، مع عدد الأذونات المطلوبة. هذه مراجعة معلومات وليست كشفًا عن الفيروسات، ولا يغيّر كنف أي إذن من تلقاء نفسه.",
                            "Lists launchable apps visible under Android package rules, with their requested permission counts. This is information review, NOT malware detection. Kanaf cannot silently change permissions."
                        ), color = secondary, style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.height(12.dp))
                        Button(onClick = onLoadApps, enabled = !busy,
                            modifier = Modifier.fillMaxWidth()) {
                            Text(tr("عرض التطبيقات المتاحة", "List visible applications"))
                        }
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(onClick = onAuditApps, enabled = !busy,
                            modifier = Modifier.fillMaxWidth()) {
                            Text(tr("فحص APK للتطبيقات الظاهرة (محدود)",
                                "Audit visible installed APKs (limited)"))
                        }
                        if (apkAuditStatus.isNotBlank()) {
                            Text(apkAuditStatus, color = secondary,
                                style = MaterialTheme.typography.bodySmall)
                        }
                        if (appsStatus.isNotBlank()) {
                            Text(appsStatus, color = secondary, style = MaterialTheme.typography.bodySmall)
                        }
                        if (appsLoaded) {
                            Spacer(Modifier.height(12.dp))
                            OutlinedTextField(value = appSearch,
                                onValueChange = { appSearch = it.take(80) },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true,
                                label = { Text(tr("بحث بالاسم أو الحزمة", "Search name or package")) })
                        }
                    }
                    if (appsLoaded) {
                        val matches = installedApps.filter {
                            it.displayName.contains(appSearch, ignoreCase = true) ||
                                it.packageName.contains(appSearch, ignoreCase = true)
                        }
                        GlassPanel(card, stroke) {
                            Text(tr("المعروض: ", "Matches: ") + matches.size +
                                tr(" (أول 60 نتيجة)", " (first 60 shown)"),
                                color = secondary, style = MaterialTheme.typography.bodySmall)
                        }
                        matches.take(60).forEach { entry ->
                            GlassPanel(card, stroke) {
                                Text(entry.displayName, color = ink,
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.SemiBold)
                                Text(entry.packageName, color = secondary,
                                    style = MaterialTheme.typography.bodySmall)
                                Text(if (entry.requestedPermissionCount != null) {
                                    tr("عدد الأذونات المعلنة: ", "Declared permission count: ") +
                                        entry.requestedPermissionCount
                                } else tr("بيانات الأذونات غير متاحة", "Permission data unavailable"),
                                    color = secondary, style = MaterialTheme.typography.bodySmall)
                                Spacer(Modifier.height(8.dp))
                                OutlinedButton(
                                    onClick = { onOpenAppDetails(entry.packageName) },
                                    modifier = Modifier.fillMaxWidth()) {
                                    Text(tr("إدارة التطبيق في أندرويد", "Manage in Android Settings"))
                                }
                            }
                        }
                    }
                }
                if (page == 8) {
                    GlassPanel(card, stroke) {
                        Text(tr("مراقبة التطبيقات بإذن المستخدم", "Opt-in app monitoring"), color = ink,
                            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        Text(tr(
                            "يرصد كنف أحداث تثبيت/تحديث التطبيقات التي يرسلها أندرويد ويعرض تنبيهًا للمراجعة اليدوية فقط. لا يفحص التطبيقات تلقائيًا بحثًا عن الفيروسات.",
                            "Kanaf observes Android package install/update broadcasts and prompts a manual review only. No automatic malware scanning of installed apps."
                        ), color = secondary, style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.height(12.dp))
                        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween) {
                            Text(tr("تنبيهات تثبيت التطبيقات", "App-install review alerts"),
                                modifier = Modifier.weight(1f), color = ink)
                            Switch(checked = watchNewApps, onCheckedChange = onWatchNewApps)
                        }
                    }
                    GlassPanel(card, stroke) {
                        Text(tr("الفحص الدوري للملفات", "Scheduled scoped file check"), color = ink,
                            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        Text(tr(
                            "اختر مجلدًا محددًا تمنح كنف حق قراءته. يعمل الفحص كل 24 ساعة تقريبًا بحسب قيود البطارية، ويطابق بصمات SHA-256 لحد أقصى 32 ملفًا مباشرًا في الدورة. لا يفحص الجهاز كله ولا يعمل كحماية فورية.",
                            "Choose a folder explicitly. Android schedules an approximate 24-hour check of up to 32 direct child files against local SHA-256 signatures. This is not a whole-device or realtime scan."
                        ), color = secondary, style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.height(12.dp))
                        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween) {
                            Text(tr("فحص مجلد محدد دوريًا", "Periodic selected-folder check"),
                                modifier = Modifier.weight(1f), color = ink)
                            Switch(checked = periodicChecks, onCheckedChange = onChangePeriodic)
                        }
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(onClick = onRunScopedCheck, enabled = periodicChecks && !busy,
                            modifier = Modifier.fillMaxWidth()) {
                            Text(tr("طلب فحص المجلد الآن", "Request folder check now"))
                        }
                        TextButton(onClick = onRefreshProtection, modifier = Modifier.fillMaxWidth()) {
                            Text(tr("تحديث نتيجة آخر فحص", "Refresh last check status"))
                        }
                        if (protectionStatus.isNotBlank()) {
                            Text(protectionStatus, color = secondary,
                                style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    GlassPanel(card, stroke) {
                        Text(tr("حدود الحماية الحالية", "Protection scope and limits"), color = ink,
                            style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Text(tr(
                            "قاعدة التوقيعات الافتراضية اختبارية. على أندرويد الحديث لا يمكن للتطبيق العادي قراءة ملفات جميع التطبيقات أو اعتراض استخدامها. لا يُصدر كنف حكم سلامة عند تعذر الفحص.",
                            "Bundled signatures are test-only. Android limits inspection of unrelated apps and private files. Kanaf does not declare unchecked content safe."
                        ), color = secondary, style = MaterialTheme.typography.bodyMedium)
                    }
                }
                if (page == 5) {
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
                    tr("نسخة تطويرية · فحص تلقائي بطلب المستخدم وقواعد محدودة", "Preview build · on-demand automatic scanning, limited test rules"),
                    modifier = Modifier.fillMaxWidth(),
                    color = secondary, style = MaterialTheme.typography.labelSmall,
                    textAlign = TextAlign.Center
                )
                }
                } // scrollable page content
            } // persistent header/navigation column
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
            .border(1.dp, outline, RoundedCornerShape(22.dp))
            .background(fill, RoundedCornerShape(22.dp))
            .padding(20.dp),
        content = content
    )
}
