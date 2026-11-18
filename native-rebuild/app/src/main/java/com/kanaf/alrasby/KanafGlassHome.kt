package com.kanaf.alrasby

import androidx.activity.compose.BackHandler
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material.icons.outlined.List
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material.icons.outlined.DateRange
import androidx.compose.material.icons.outlined.Build
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.kanaf.alrasby.engine.LinkDomainReputation
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
import com.kanaf.alrasby.engine.KanafUrlAi
import com.kanaf.alrasby.engine.KanafPrivacyDisclosure
import com.kanaf.alrasby.engine.DnsProviderStore
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
    aiModelStatus: String,
    urlRiskModel: KanafUrlAi?,
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
    privateDnsActionStatus: String,
    onOpenPrivateDnsSettings: () -> Unit,
    onChoosePrivateDns: (String?) -> Unit,
    selectedDnsProvider: String,
    onSelectDnsProvider: (String) -> Unit,
    dnsSessionStats: String,
    dnsBusy: Boolean,
    dnsCoverageStatus: String,
    onRefreshDnsStats: () -> Unit,
    onCheckDnsCoverage: () -> Unit,
    onAddDnsQuickTile: () -> Unit,
    dnsQuickTileStatus: String,
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
    var showPrivacyPolicy by remember { mutableStateOf(false) }
    var customPrivateDns by rememberSaveable { mutableStateOf("") }
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
    var headerHeight by remember { mutableIntStateOf(0) }
    val headerPadding = with(LocalDensity.current) { headerHeight.toDp() }
    val scrollState = rememberScrollState()
    LaunchedEffect(page) { scrollState.scrollTo(0) }
    // Refresh only while the DNS screen is visible, with no domain-history storage.
    LaunchedEffect(page, vpnRequested) {
        if (page == 9 && vpnRequested) {
            while (true) {
                onRefreshDnsStats()
                delay(2000)
            }
        }
    }
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
            title = { Text(tr(KanafPrivacyDisclosure.VPN_TITLE_AR,
                KanafPrivacyDisclosure.VPN_TITLE_EN)) },
            text = {
                Column(Modifier.heightIn(max = 340.dp).verticalScroll(rememberScrollState())) {
                    Text(tr(KanafPrivacyDisclosure.VPN_AR, KanafPrivacyDisclosure.VPN_EN))
                }
            },
            confirmButton = {
                TextButton(onClick = { confirmVpn = false; onVpnToggle(true) }) {
                    Text(tr("أوافق وأفعّل DNS", "Agree & enable DNS"))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmVpn = false }) { Text(tr("إلغاء", "Cancel")) }
            }
        )
    }
    if (showPrivacyPolicy) {
        AlertDialog(
            onDismissRequest = { showPrivacyPolicy = false },
            title = { Text(tr("سياسة خصوصية كنف", "Kanaf privacy policy")) },
            text = {
                Column(Modifier.heightIn(max = 400.dp).verticalScroll(rememberScrollState())) {
                    Text(tr(KanafPrivacyDisclosure.PRIVACY_AR,
                        KanafPrivacyDisclosure.PRIVACY_EN))
                }
            },
            confirmButton = {
                TextButton(onClick = { showPrivacyPolicy = false }) {
                    Text(tr("إغلاق", "Close"))
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
        LinkInspector.Signal.AD_TRACKER -> tr("نطاق إعلانات أو تتبع معروف، وليس دليلًا على برمجية خبيثة", "Known ad/tracker host; not proof of malware")
    }
    val dark = isSystemInDarkTheme()
    val background = if (dark) Night else Color(0xFFF2F7F7)
    val ink = if (dark) Color(0xFFF0FBFA) else Night
    val secondary = if (dark) Color(0xFFB4CDCF) else Color(0xFF47666C)
    val card = if (dark) Color(0xFF153F48).copy(alpha = 0.78f)
        else Color(0xFFB9DDD5).copy(alpha = 0.55f)
    val stroke = if (dark) Color(0xFF80D9C9).copy(alpha = 0.28f)
        else Color(0xFF70ABA0).copy(alpha = 0.30f)

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
            Box(
                Modifier.widthIn(max = 680.dp).fillMaxWidth().fillMaxHeight()
                    .windowInsetsPadding(WindowInsets.safeDrawing)
                    .padding(horizontal = 14.dp, vertical = 10.dp)
            ) {
                // Keep header and navigation reachable while lengthy cards scroll.
                Column(
                    Modifier.fillMaxSize()
                        .verticalScroll(scrollState)
                        .padding(top = headerPadding + 10.dp, bottom = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(9.dp)
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
                            modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)
                                .testTag("device_scan_button"),
                            shape = RoundedCornerShape(20.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (dark) Aqua else Teal,
                                contentColor = if (dark) Night else Color.White
                            )
                        ) {
                            Text(if (busy) tr("جارٍ الفحص…", "Scanning…")
                                else tr("فحص الجهاز الآن", "Scan device now"),
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
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
                    val homeSections = KanafSection.entries.filter { it.id !in hiddenSections } + listOf(null, null)
                    homeSections.chunked(3).forEachIndexed { rowIndex, row ->
                        Row(Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            row.forEachIndexed { columnIndex, section ->
                                val action = rowIndex * 3 + columnIndex - (homeSections.size - 2)
                                val title = when (section) {
                                    KanafSection.SCAN -> tr("الفحص", "Scan")
                                    KanafSection.LINKS -> tr("الروابط", "Links")
                                    KanafSection.APPS -> tr("التطبيقات", "Apps")
                                    KanafSection.VAULT -> tr("الخزنة", "Vault")
                                    KanafSection.PROTECTION -> tr("الحماية", "Protection")
                                    KanafSection.HISTORY -> tr("السجل", "History")
                                    KanafSection.ENGINES -> tr("المحركات", "Engines")
                                    null -> if (action == 0) tr("خيارات الفحص", "Scan options") else tr("حماية DNS", "DNS protection")
                                }
                                val symbol = when (section) {
                                    KanafSection.SCAN -> Icons.Outlined.Search
                                    KanafSection.LINKS -> Icons.Outlined.Share
                                    KanafSection.APPS -> Icons.Outlined.List
                                    KanafSection.VAULT -> Icons.Outlined.Lock
                                    KanafSection.PROTECTION -> Icons.Outlined.Warning
                                    KanafSection.HISTORY -> Icons.Outlined.DateRange
                                    KanafSection.ENGINES -> Icons.Outlined.Build
                                    null -> if (action == 0) Icons.Outlined.Search else Icons.Outlined.Share
                                }
                                Surface(
                                    onClick = { page = when {
                                        section == null -> if (action == 0) 10 else 9
                                        section == KanafSection.SCAN -> 10
                                        else -> section.page
                                    } },
                                    modifier = Modifier.weight(1f).testTag(
                                        if (section != null) "nav_" + section.id
                                        else if (action == 0) "open_scan_tools" else "open_dns_page"),
                                    shape = RoundedCornerShape(18.dp), color = card,
                                    border = androidx.compose.foundation.BorderStroke(1.dp, stroke)
                                ) {
                                    Column(
                                        Modifier.fillMaxWidth().heightIn(min = 78.dp)
                                            .padding(horizontal = 6.dp, vertical = 12.dp),
                                        horizontalAlignment = Alignment.CenterHorizontally,
                                        verticalArrangement = Arrangement.spacedBy(6.dp)
                                    ) {
                                        Icon(symbol, contentDescription = null,
                                            tint = if (dark) Aqua else Teal,
                                            modifier = Modifier.size(22.dp))
                                        Text(title, color = ink,
                                            style = MaterialTheme.typography.labelMedium,
                                            textAlign = TextAlign.Center)
                                    }
                                }
                            }
                            repeat(3 - row.size) { Spacer(Modifier.weight(1f)) }
                        }
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
                }
                if (page == 9) {
                    GlassPanel(card, stroke) {
                        Text(tr("Kanaf DNS", "Kanaf DNS"), color = ink,
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold)
                        Text(if (BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY)
                            tr("حماية DNS من البرمجيات الخبيثة والتصيد عبر مزوّد مشفر، دون حجب الإعلانات.",
                                "Encrypted malware/phishing DNS protection without ad blocking.")
                        else tr("مرشح محلي للإعلانات والتتبع، مع DNS مشفر واختيار مزوّد واحد.",
                                "Local ad/tracker blocking with encrypted DNS and one selected provider."),
                            color = secondary, style = MaterialTheme.typography.bodySmall)
                        Row(
                            modifier = Modifier.fillMaxWidth().heightIn(min = 60.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(
                                    if (vpnRequested) tr("الحماية مفعّلة", "Filtering active")
                                    else tr("الحماية متوقفة", "Filtering off"),
                                    color = ink, style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    if (vpnRequested)
                                        tr("الاتصال عبر المزوّد المختار", "Using selected provider")
                                    else tr("فعّل بعد اختيار المزوّد", "Choose a provider, then enable"),
                                    color = secondary, style = MaterialTheme.typography.bodySmall
                                )
                            }
                            Switch(
                                checked = vpnRequested,
                                enabled = if (vpnRequested) true else !dnsBusy && privateDnsCompatible,
                                onCheckedChange = { enabled ->
                                    if (enabled) confirmVpn = true else onVpnToggle(false)
                                },
                                modifier = Modifier.testTag("dns_filter_switch")
                            )
                        }
                        OutlinedButton(
                            onClick = onAddDnsQuickTile,
                            modifier = Modifier.fillMaxWidth()
                                .heightIn(min = 48.dp).testTag("dns_add_quick_tile"),
                            shape = RoundedCornerShape(16.dp)
                        ) {
                            Text(tr("إضافة مفتاح Kanaf DNS للإعدادات السريعة",
                                "Add Kanaf DNS to Quick Settings"))
                        }
                        if (dnsQuickTileStatus.isNotBlank()) {
                            Text(dnsQuickTileStatus, color = secondary,
                                style = MaterialTheme.typography.bodySmall)
                        }
                        if (!privateDnsCompatible) {
                            Text(tr(
                                "المزوّد الصارم في إعدادات الهاتف يمنع تشغيل المرشح؛ اختر «تلقائي» من إعدادات Android.",
                                "A strict Android Private DNS provider blocks Kanaf; choose Automatic in phone settings."
                            ), color = secondary, style = MaterialTheme.typography.bodySmall)
                        }
                    }

                    GlassPanel(card, stroke) {
                        Text(tr("اختر مزوّد DNS", "Choose DNS provider"),
                            color = ink, style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold)
                        Text(tr(
                            "فعّل نطاقًا واحدًا. يمكنك التبديل بين المزوّدين أثناء التشغيل بعد التحقق من الاتصال المشفّر.",
                            "Enable one provider. Switch securely while filtering after the new provider is verified."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                        for (host in DnsProviderStore.choices) {
                            val chosen = selectedDnsProvider == host
                            val providerActive = chosen && vpnRequested
                            val canToggle = !dnsBusy && (providerActive || privateDnsCompatible)
                            val subtitle = when (host) {
                                DnsProviderStore.PLAY_SECURITY ->
                                    tr("حماية البرمجيات الخبيثة والتصيد، دون حجب الإعلانات",
                                       "Malware/phishing protection; no ad blocking")
                                "dns.adguard.com" ->
                                    tr("اسم قديم لنفس خادم AdGuard القياسي",
                                        "Legacy alias of the standard AdGuard server")
                                "family.adguard-dns.com" ->
                                    tr("إعلانات وتتبع وحماية عائلية", "Ads, tracking and family filtering")
                                else ->
                                    tr("إعلانات وتتبع", "Ads and tracking")
                            }
                            fun requestActivation() {
                                if (privateDnsCompatible) {
                                    onSelectDnsProvider(host)
                                    if (!vpnRequested) confirmVpn = true
                                }
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth()
                                    .heightIn(min = 60.dp)
                                    .clickable(enabled = canToggle) {
                                        if (providerActive) onVpnToggle(false)
                                        else requestActivation()
                                    }
                                    .testTag("dns_provider_" + host.replace('.', '_')),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text(host, color = ink,
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = if (chosen)
                                            FontWeight.Bold else FontWeight.Medium)
                                    Text(
                                        subtitle + if (chosen && !vpnRequested)
                                            tr(" · محفوظ للاستخدام", " · saved choice") else "",
                                        color = secondary,
                                        style = MaterialTheme.typography.labelSmall)
                                }
                                Switch(
                                    checked = providerActive,
                                    enabled = canToggle,
                                    onCheckedChange = { enable ->
                                        if (enable) requestActivation()
                                        else if (providerActive) onVpnToggle(false)
                                    },
                                    modifier = Modifier.testTag(
                                        "dns_provider_switch_" + host.replace('.', '_')
                                    )
                                )
                            }
                        }
                        if (vpnStatus.isNotBlank())
                            Text(vpnStatus, color = secondary,
                                style = MaterialTheme.typography.bodySmall,
                                maxLines = 4)
                    }

                    GlassPanel(card, stroke) {
                        Text(tr("اتصال DNS والتغطية", "DNS connection & coverage"),
                            color = ink, style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold)
                        Text(tr(
                            "عدادات محلية دون سجل نطاقات. يدعم كنف طلبات DNS عبر IPv4 وIPv6 الموجهة إلى خادمه، لكن فحص الاتصال لا يثبت منع كل التجاوزات.",
                            "Session-only counters without domain history. Kanaf handles IPv4 and IPv6 queries to its DNS servers, but this check cannot prove leak prevention."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                        Text(dnsSessionStats, color = ink,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.testTag("dns_session_stats"))
                        Row(Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(
                                onClick = onRefreshDnsStats,
                                modifier = Modifier.weight(1f).heightIn(min = 48.dp)
                                    .testTag("dns_refresh_stats")
                            ) { Text(tr("تحديث العدادات", "Refresh counts"),
                                style = MaterialTheme.typography.labelMedium) }
                            OutlinedButton(
                                onClick = onCheckDnsCoverage,
                                modifier = Modifier.weight(1f).heightIn(min = 48.dp)
                                    .testTag("dns_check_coverage")
                            ) { Text(tr("فحص الاتصال", "Check connection"),
                                style = MaterialTheme.typography.labelMedium) }
                        }
                        if (dnsCoverageStatus.isNotBlank()) {
                            Text(dnsCoverageStatus, color = secondary,
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.testTag("dns_coverage_status"))
                        }
                    }

                    if (privateDnsAvailable) GlassPanel(card, stroke) {
                        Text(tr("DNS الخاص بالنظام", "Android Private DNS"),
                            color = ink, style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold)
                        Text(privateDnsStatus, color = secondary,
                            style = MaterialTheme.typography.bodySmall)
                        Row(Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            OutlinedButton(
                                onClick = onOpenPrivateDnsSettings,
                                modifier = Modifier.weight(1f).heightIn(min = 48.dp)
                                    .testTag("dns_system_off")
                            ) { Text(tr("متوقف", "Off")) }
                            OutlinedButton(
                                onClick = onOpenPrivateDnsSettings,
                                modifier = Modifier.weight(1f).heightIn(min = 48.dp)
                                    .testTag("dns_system_auto")
                            ) { Text(tr("تلقائي", "Automatic")) }
                        }
                        Text(tr(
                            "الزران يفتحان إعدادات Android مباشرة؛ لا يستطيع كنف تغيير وضع النظام دون صلاحية خاصة. وضع «تلقائي» متوافق مع مرشح كنف المشفّر.",
                            "Both buttons open Android settings directly. Kanaf cannot change the system mode without special permission. Automatic works with encrypted Kanaf DNS."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                    }

                    TextButton(
                        onClick = { dnsAdvanced = !dnsAdvanced },
                        modifier = Modifier.fillMaxWidth().testTag("dns_advanced_options")
                    ) {
                        Text(if (dnsAdvanced)
                            tr("إخفاء الخيارات المتقدمة", "Hide advanced options")
                            else tr("خيارات إضافية", "More options"))
                    }
                    if (dnsAdvanced) {
                        GlassPanel(card, stroke) {
                            Text(tr("مزوّد خاص في إعدادات Android",
                                "Custom Android Private DNS provider"),
                                color = ink, style = MaterialTheme.typography.titleMedium)
                            OutlinedTextField(
                                value = customPrivateDns,
                                onValueChange = { customPrivateDns = it.take(253) },
                                modifier = Modifier.fillMaxWidth()
                                    .testTag("dns_custom_provider"),
                                singleLine = true,
                                label = { Text(tr("اسم المزوّد", "Provider hostname")) }
                            )
                            OutlinedButton(
                                onClick = { onChoosePrivateDns(customPrivateDns.trim()) },
                                enabled = customPrivateDns.isNotBlank(),
                                modifier = Modifier.fillMaxWidth()
                                    .testTag("dns_add_provider")
                            ) {
                                Text(tr("نسخ الاسم وفتح إعدادات Android",
                                    "Copy hostname & open Android settings"))
                            }
                            OutlinedButton(onClick = onVpnRefresh,
                                modifier = Modifier.fillMaxWidth()) {
                                Text(tr("تحديث حالة Kanaf DNS", "Refresh Kanaf DNS status"))
                            }
                            if (privateDnsActionStatus.isNotBlank()) {
                                Text(privateDnsActionStatus, color = secondary,
                                    style = MaterialTheme.typography.bodySmall)
                            }
                        }
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
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                            shape = RoundedCornerShape(16.dp)
                        ) {
                            Text(tr("تحليل محلي", "Inspect locally"))
                        }
                        Text(tr(
                            "تحليل محلي دون فتح الرابط أو إرسال بياناته. عند توافر Kanaf AI التجريبي تُعرض درجة احتمالية مبنية على نص الرابط وبيانات تاريخية، لا فحص سمعة أو ضمان سلامة.",
                            "Local analysis without opening or uploading the URL. When experimental Kanaf AI is included, its historical URL-text score is advisory; no site reputation check or safety guarantee."
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
                        report.items.forEachIndexed { index, item ->
                            GlassPanel(card, stroke) {
                                Text(item.host ?: tr("مضيف غير قابل للتحليل", "Unparseable host"),
                                    color = ink, style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.SemiBold)
                                Text(item.url.take(240) + if (item.url.length > 240) "…" else "",
                                    color = secondary, style = MaterialTheme.typography.bodySmall)
                                item.host?.takeIf(LinkDomainReputation::supports)?.let { host ->
                                    key(report, index, item.url) {
                                        val scope = rememberCoroutineScope()
                                        var checking by remember { mutableStateOf(false) }
                                        var reputation by remember {
                                            mutableStateOf<LinkDomainReputation.Result?>(null)
                                        }
                                        Text(tr("يُرسل اسم النطاق فقط إلى Cloudflare عبر DNS مشفّر.",
                                            "Only the hostname is sent to Cloudflare over encrypted DNS."),
                                            color = secondary, style = MaterialTheme.typography.bodySmall)
                                        TextButton(enabled = !checking, onClick = {
                                            checking = true
                                            reputation = null
                                            scope.launch {
                                                try {
                                                    reputation = withContext(Dispatchers.IO) {
                                                        LinkDomainReputation.check(host)
                                                    }
                                                } finally {
                                                    checking = false
                                                }
                                            }
                                        }) {
                                            Text(if (checking) tr("جارٍ التحقق…", "Checking…")
                                                else tr("فحص النطاق عبر Cloudflare", "Check domain with Cloudflare"))
                                        }
                                        when (reputation) {
                                            LinkDomainReputation.Result.BLOCKED -> Text(tr(
                                                "أعاد Cloudflare Security عنوان الحجب لهذا النطاق.",
                                                "Cloudflare Security returned a blocking address."),
                                                color = MaterialTheme.colorScheme.error)
                                            LinkDomainReputation.Result.NOT_BLOCKED -> Text(tr(
                                                "لم يحجب Cloudflare النطاق. سلامة الصفحة غير مؤكدة.",
                                                "Cloudflare did not block the domain. Page safety is unverified."),
                                                color = secondary)
                                            LinkDomainReputation.Result.UNAVAILABLE -> Text(tr(
                                                "تعذّر الحصول على نتيجة DNS قابلة للتفسير.",
                                                "No conclusive DNS response was available."), color = secondary)
                                            null -> Unit
                                        }
                                    }
                                }
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
                                if (item.verdict != LinkInspector.Verdict.INVALID) {
                                    val urlScore = urlRiskModel?.evaluate(item.url)
                                    if (urlScore != null) {
                                        Spacer(Modifier.height(8.dp))
                                        Text(tr(
                                            "Kanaf AI تجريبي — مؤشر تشابه مع روابط التصيّد في بيانات التدريب: " +
                                                (urlScore * 100).toInt() + "%؛ ليس حكمًا بوجود تصيّد أو تأكيدًا للسلامة.",
                                            "Experimental Kanaf AI — similarity to historical phishing URL patterns: " +
                                                (urlScore * 100).toInt() + "%. Not a phishing verdict or proof of safety."
                                        ), modifier = Modifier.testTag("url_ai_score"),
                                            color = if (dark) Aqua else Teal,
                                            style = MaterialTheme.typography.bodySmall)
                                    } else if (urlRiskModel == null) {
                                        Text(tr("Kanaf AI للروابط غير مفعّل في هذه النسخة.",
                                            "Kanaf AI URL model not enabled in this build."),
                                            color = secondary,
                                            style = MaterialTheme.typography.bodySmall)
                                    }
                                }
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
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
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
                            "فحص التطبيقات المثبتة والملفات المشتركة بطلب المستخدم متاح من الرئيسية، لكن المحركين الأصليين يفحصان الملفات حتى 16 ميجابايت وبقواعد اختبارية. لا تتوفر قاعدة فيروسات إنتاجية أو حماية فورية شاملة.",
                            "On-demand scanning of installed APKs and accessible shared files is available on Home. Native checks are capped at 16 MiB and use test-only rules; no production malware database or full real-time protection."
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
                        Text(tr("Kanaf AI — تحليل محلي", "Kanaf AI — on-device analysis"),
                            color = ink, style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold)
                        Text(aiModelStatus, color = secondary,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.testTag("kanaf_ai_status"))
                        Text(tr(
                            "نموذج الروابط التجريبي منفصل عن نموذج APK. كلاهما محلي، ولا يصل للرسائل أو المكالمات خفية ولا يحذف الملفات. لا تُعتمد درجات النموذج التجريبي لتحديد سلامة الروابط.",
                            "The experimental URL model is separate from APK scanning. Both are offline and never secretly access messages/calls or delete files. Pilot scores do not establish link safety."
                        ), color = secondary, style = MaterialTheme.typography.bodySmall)
                    }
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
                                        .heightIn(min = 48.dp).padding(vertical = 6.dp),
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
                            Row(Modifier.fillMaxWidth().heightIn(min = 48.dp),
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
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(onClick = { showPrivacyPolicy = true },
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)
                                .testTag("kanaf_privacy_policy")) {
                            Text(tr("قراءة سياسة الخصوصية", "Read privacy policy"))
                        }
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
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)
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
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                            shape = RoundedCornerShape(16.dp)) {
                            Text(tr("إضافة ملف إلى الخزنة", "Add file to vault"))
                        }
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(onClick = { confirmQuarantine = true }, enabled = !busy,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
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
                            "اختر مجلدًا محددًا تمنح كنف حق قراءته. يعمل الفحص كل 24 ساعة تقريبًا بحسب قيود البطارية، ويطابق بصمات SHA-256 لحد أقصى 32 ملفًا ضمن المجلد ومجلداته الفرعية في الدورة. لا يفحص الجهاز كله ولا يعمل كحماية فورية.",
                            "Choose a folder explicitly. Android schedules an approximate 24-hour check of up to 32 files in the selected folder and its subfolders against local SHA-256 signatures. This is not a whole-device or realtime scan."
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
                        .clip(RoundedCornerShape(50))
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
                Column(
                    Modifier.fillMaxWidth()
                        .onSizeChanged { headerHeight = it.height }
                        .clip(RoundedCornerShape(bottomStart = 20.dp, bottomEnd = 20.dp))
                        .background(Brush.verticalGradient(listOf(
                            card.copy(alpha = 0.88f), card.copy(alpha = 0.65f)
                        )))
                        .padding(horizontal = 8.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        Modifier.size(48.dp).clip(RoundedCornerShape(14.dp))
                            .background(Color(0xFFD4F0EB)),
                        contentAlignment = Alignment.Center
                    ) {
                        Image(painterResource(R.drawable.kanaf_launcher_foreground),
                            contentDescription = null, modifier = Modifier.size(48.dp))
                    }
                    Spacer(Modifier.width(8.dp))
                    Column(Modifier.weight(1f)) {
                        Text(tr("كنف", "Kanaf"), color = ink,
                            style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                        Text(tr("مركز الأمان والخصوصية", "Security & privacy studio"),
                            color = secondary, style = MaterialTheme.typography.labelSmall)
                    }
                    OutlinedButton(
                        onClick = { page = if (page != 0) 0 else 5 },
                        modifier = Modifier.testTag("settings_button"),
                        shape = RoundedCornerShape(16.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            containerColor = if (page == 5) Teal.copy(alpha = 0.14f) else card,
                            contentColor = if (dark) Aqua else Teal
                        ),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                    ) {
                        Text(if (page != 0) "⌂" else "⚙",
                            style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.width(5.dp))
                        Text(if (page != 0) tr("الرئيسية", "Home")
                            else tr("الإعدادات", "Settings"),
                            style = MaterialTheme.typography.labelMedium)
                    }
                }
                if (busy && page != 0) {
                    Surface(
                        color = card,
                        shape = RoundedCornerShape(16.dp),
                        tonalElevation = 2.dp
                    ) {
                        Row(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                            Text(tr("العملية مستمرة", "Operation in progress"),
                                color = ink, style = MaterialTheme.typography.labelLarge)
                            if (autoScanProgress.isNotBlank()) {
                                Text(autoScanProgress, color = secondary,
                                    style = MaterialTheme.typography.labelSmall,
                                    modifier = Modifier.weight(1f))
                            }
                        }
                    }
                }
                }
            } // header overlays the scrolling cards
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
            .shadow(6.dp, RoundedCornerShape(22.dp), clip = false,
                ambientColor = Color(0xFF146C70).copy(alpha = 0.08f),
                spotColor = Color(0xFF0A1729).copy(alpha = 0.07f))
            .clip(RoundedCornerShape(22.dp))
            .background(Brush.linearGradient(listOf(
                fill.copy(alpha = (fill.alpha + 0.06f).coerceAtMost(1f)),
                fill,
                fill.copy(alpha = (fill.alpha - 0.08f).coerceAtLeast(0f))
            )))
            .border(1.dp, outline, RoundedCornerShape(22.dp))
            .padding(horizontal = 14.dp, vertical = 12.dp),
        content = content
    )
}
