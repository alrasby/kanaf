package com.kanaf.alrasby

import android.app.Activity
import android.content.Intent
import android.os.Environment
import android.provider.Settings
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import com.kanaf.alrasby.engine.AutomaticDeviceScan
import com.kanaf.alrasby.engine.ThreatRuleUpdater
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner
import com.kanaf.alrasby.engine.PrivateDnsCompatibility
import com.kanaf.alrasby.engine.PrivateDnsSettingsNavigator
import android.net.Uri
import android.net.VpnService
import com.kanaf.alrasby.engine.KanafDnsVpnService
import com.kanaf.alrasby.engine.PrivateDnsToggle
import com.kanaf.alrasby.engine.DnsProviderStore
import com.kanaf.alrasby.engine.DnsCoverageProbe
import com.kanaf.alrasby.engine.KanafDnsTileService
import android.app.StatusBarManager
import android.content.ComponentName
import android.graphics.drawable.Icon
import android.Manifest
import android.os.Build
import android.content.pm.PackageManager
import androidx.work.WorkInfo
import androidx.lifecycle.Observer
import androidx.work.WorkManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.kanaf.alrasby.engine.ThreatFeatureVector
import com.kanaf.alrasby.engine.VerifiedLinearThreatModel
import com.kanaf.alrasby.engine.KanafUrlAi
import com.kanaf.alrasby.engine.ThreatModel
import com.kanaf.alrasby.engine.TrustJourney
import com.kanaf.alrasby.engine.ThreatEvidence
import com.kanaf.alrasby.engine.AntivirusEngine
import com.kanaf.alrasby.engine.HashSignatureEngine
import com.kanaf.alrasby.engine.EngineConsensus
import com.kanaf.alrasby.engine.ScanEvidenceText
import com.kanaf.alrasby.engine.NativeScannerBridge
import com.kanaf.alrasby.engine.SignatureRepository
import com.kanaf.alrasby.engine.DexHeaderInspector
import com.kanaf.alrasby.engine.ApkStructureInspector
import com.kanaf.alrasby.engine.ZipInspector
import com.kanaf.alrasby.engine.LinkInspector
import com.kanaf.alrasby.engine.EncryptedVault
import com.kanaf.alrasby.engine.ProtectionControl
import com.kanaf.alrasby.engine.ScopedDeviceScan
import com.kanaf.alrasby.engine.SafQuarantine
import com.kanaf.alrasby.engine.ProductionFeedInstaller
import com.kanaf.alrasby.engine.InstalledAppAudit
import com.kanaf.alrasby.engine.InstalledAppInventory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private var incomingSharedText by mutableStateOf<String?>(null)
    private var incomingSharedFile by mutableStateOf<Uri?>(null)
    private var shareRequest by mutableLongStateOf(0L)
    private fun extractSharedFile(from: Intent?): Uri? = runCatching {
        if (from?.action != Intent.ACTION_SEND) return@runCatching null
        @Suppress("DEPRECATION")
        val uri = from.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
        uri?.takeIf { it.scheme == "content" }
    }.getOrNull()

    private fun extractSharedText(from: Intent?): String? {
        if (from?.action != Intent.ACTION_SEND || from.type != "text/plain") return null
        return from.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
            ?.take(LinkInspector.MAX_TEXT_CHARS + 1)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        incomingSharedText = extractSharedText(intent)
        incomingSharedFile = extractSharedFile(intent)
        shareRequest++
        PrivateDnsToggle.recoverIfStopped(this)
        val deviceScan = ViewModelProvider(this)[DeviceScanSession::class.java]
        setContent {
            MaterialTheme { KanafScreen(this, incomingSharedText, incomingSharedFile, shareRequest, deviceScan) }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        incomingSharedText = extractSharedText(intent)
        incomingSharedFile = extractSharedFile(intent)
        shareRequest++
    }
}

@Composable
private fun KanafScreen(
    activity: Activity, sharedText: String?, sharedFile: Uri?, shareRequest: Long,
    deviceScan: DeviceScanSession
) {
    val scope = rememberCoroutineScope()
    val uiPreferences = remember(activity) { KanafUiPreferences(activity) }
    var uiLanguage by remember { mutableStateOf(uiPreferences.language()) }
    val arabic = uiLanguage.isArabic()
    fun localized(ar: String, en: String) = if (arabic) ar else en
    var hiddenSections by remember { mutableStateOf(uiPreferences.hiddenSections()) }
    var status by remember {
        mutableStateOf(KanafMessage("استخدم زر الفحص لمراجعة الجهاز", "Tap Scan to inspect your device"))
    }
    var otherTaskBusy by remember { mutableStateOf(false) }
    val deviceScanState by deviceScan.state.collectAsState()
    val automaticScanActive = deviceScanState.active
    val busy = otherTaskBusy || automaticScanActive
    var selfTestStatus by remember { mutableStateOf(KanafMessage.EMPTY) }
    var hasScanReport by remember { mutableStateOf(false) }
    var lastManualUri by remember { mutableStateOf<Uri?>(null) }
    var manualScanSummary by remember { mutableStateOf(KanafMessage.EMPTY) }
    var watchNewApps by remember { mutableStateOf(ProtectionControl.installWatchEnabled(activity)) }
    var periodicChecks by remember { mutableStateOf(ProtectionControl.periodicEnabled(activity)) }
    var protectionStatus by remember {
        mutableStateOf(KanafMessage.fromScheduledStatus(ProtectionControl.lastResult(activity)))
    }
    val notificationPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (!granted) protectionStatus = KanafMessage(
            "أذونات الإشعارات معطلة في أندرويد. تبقى الميزات بحاجة إلى موافقة المستخدم.",
            "Android notifications are disabled. Protection features still require opt-in."
        )
    }
    val folderPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { tree ->
        if (tree != null) {
            runCatching {
                activity.contentResolver.takePersistableUriPermission(
                    tree, Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
                ProtectionControl.enableTreeChecks(activity, tree)
                periodicChecks = true
                ProtectionControl.checkNow(activity)
                protectionStatus = KanafMessage(
                    "تم طلب فحص المجلد الآن وتفعيل الفحص الدوري كل 24 ساعة تقريبًا.",
                    "Folder check requested now; periodic checks scheduled approximately every 24 hours."
                )
            }.onFailure {
                protectionStatus = KanafMessage(
                    "تعذر الوصول للمجلد: ", "Folder access unavailable: "
                ).append(it.javaClass.simpleName)
            }
        }
    }
    var deviceScanStatus by remember { mutableStateOf(KanafMessage.EMPTY) }
    val autoScanProgress = deviceScanState.progress?.let { progress ->
        when (progress.phase) {
            "inventory" -> localized("جارٍ حصر التطبيقات…", "Listing installed apps…")
            "apps" -> localized(
                "التطبيقات المتاحة: ${progress.applications} · حزم APK التي بدأت معالجتها: ${progress.appApks}",
                "Available apps: ${progress.applications} · APKs started: ${progress.appApks}")
            "files" -> localized("الملفات المشتركة: ${progress.sharedFiles}",
                "Shared files: ${progress.sharedFiles}")
            "done" -> localized("جارٍ إعداد التقرير…", "Preparing the report…")
            else -> ""
        }
    }.orEmpty()
    var scanAccessStatus by remember { mutableStateOf(KanafMessage.EMPTY) }
    var updateRulesStatus by remember { mutableStateOf(KanafMessage.EMPTY) }
    var sharedStorageAccess by remember {
        mutableStateOf(if (Build.VERSION.SDK_INT >= 30)
            Environment.isExternalStorageManager()
        else activity.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) ==
            PackageManager.PERMISSION_GRANTED)
    }
    val manualScanSession = remember { AtomicLong(0) }
    val scopedScanSession = remember { AtomicLong(0) }
    val scopedScanCancellation = remember { AtomicBoolean(false) }
    val selfTestSession = remember { AtomicLong(0) }
    var manualScanActive by remember { mutableStateOf(false) }
    var scopedScanActive by remember { mutableStateOf(false) }
    var engineSelfTestActive by remember { mutableStateOf(false) }
    val scanHistoryArabic = remember { mutableStateListOf<String>() }
    val scanHistoryEnglish = remember { mutableStateListOf<String>() }
    var askFilesBeforeScan by rememberSaveable { mutableStateOf(false) }
    var scanOnFilesPermissionReturn by remember { mutableStateOf(false) }
    fun startAutomaticDeviceScan() {
        if (!busy && !deviceScan.state.value.active) deviceScan.start(sharedStorageAccess)
    }
    LaunchedEffect(deviceScanState.active, deviceScanState.result, deviceScanState.interruption) {
        deviceScanState.interruption?.let { deviceScanStatus = it.description() }
        if (automaticScanActive) {
            deviceScanStatus = KanafMessage(
                "جارٍ فحص التطبيقات والملفات المتاحة.",
                "Scanning installed apps and accessible files."
            )
        }
        deviceScanState.result?.let { result ->
            deviceScanStatus = result.fold(
                onSuccess = { scan ->
                    fun failureStages(arabic: Boolean): String {
                        if (scan.workerFailureStages.isEmpty()) return ""
                        val label = if (arabic) "آخر مراحل أبلغ عنها المحرك قبل التوقف"
                            else "Last scanner stages reported before interruption"
                        val stages = scan.workerFailureStages.joinToString(" · ") {
                            com.kanaf.alrasby.engine.ScanEvidenceText.workerStage(it, arabic)
                        }
                        return "$label: $stages.\n"
                    }
                    val noteAr = if (scan.sharedStorageGranted)
                        "تمت مراجعة التخزين المشترك المتاح." else
                        "لم يُمنح الوصول للملفات المشتركة؛ فُحصت حزم التطبيقات فقط."
                    val noteEn = if (scan.sharedStorageGranted)
                        "Accessible shared storage was included." else
                        "Shared files access not granted; only installed app packages were checked."
                    val evidenceAr = scan.findings.joinToString("\n") {
                        it.source + " — " + if (it.isSignature)
                            com.kanaf.alrasby.engine.ThreatFamily.label(it.label, true) +
                                " (" + it.label + ")" else
                            "تحذير في بنية الأرشيف؛ ليس إثبات إصابة"
                    }
                    val evidenceEn = scan.findings.joinToString("\n") {
                        it.source + " — " + if (it.isSignature)
                            com.kanaf.alrasby.engine.ThreatFamily.label(it.label, false) +
                                " (" + it.label + ")" else
                            "Archive structure warning; not a malware diagnosis"
                    }
                    KanafMessage(
                        "انتهت المحاولة: تطبيقات=" + scan.installedApps +
                            "، ملفات APK=" + scan.appApksAttempted +
                            "، ملفات مشتركة=" + scan.sharedFilesAttempted +
                            "، ملفات APK محفوظة=" + scan.storedApksAttempted +
                            "، بصمات محسوبة=" + scan.hashed +
                            "، ملفات أُرسلت إلى المحركات=" + scan.nativeChecked +
                            " (تطبيقات=" + scan.nativeInstalledAttempts +
                            "، ملفات مشتركة=" + scan.nativeSharedAttempts + ")" +
                            "، تطابقات تهديد=" + scan.matches + "، عينات اختبار=" + scan.testSamples +
                            "، ملفات بفحص غير مكتمل=" + scan.incomplete +
                            "، تحذيرات بنيوية=" + scan.structuralWarnings +
                            ".\n" +
                            "فحوص المحركات المكتملة: ClamAV ${scan.clamavCompleted} · YARA-X ${scan.yaraCompleted}.\n" +
                            (if (scan.truncated) "انتهى الفحص قبل تغطية جميع الملفات المتاحة.\n" else "") +
                            (if (scan.inventoryIssues > 0) "عناصر تعذّر حصرها: ${scan.inventoryIssues}.\n" else "") +
                            (if (scan.workerFailures > 0) "أعطال عملية المحرك: ${scan.workerFailures}.\n" else "") +
                            failureStages(true) +
                            (if (scan.yaraPaused) "توقف YARA-X بقية الجلسة بعد تعطل عملية الفحص.\n" else "") +
                            (if (scan.nativePaused) "أُوقف فحص المحركات لهذه الجلسة، واستمر فحص البصمات.\n" else "") +
                            noteAr + "\n" +
                            "أسباب عدم الاكتمال وعدد الملفات لكل سبب (قد يجتمع أكثر من سبب في ملف):\n" + scan.incompleteReasons.entries.sortedByDescending { it.value }.joinToString("\n") {
                                com.kanaf.alrasby.engine.ScanEvidenceText.reason(it.key, true) + " × " + it.value
                            } + "\n" + evidenceAr.take(2200) +
                            "\nبصمات أندرويد من ESET وقواعد محتوى Linux/ELF من ESET وReversingLabs. تكرار البصمة في المحركات مصدر واحد. عدم التطابق لا يثبت السلامة. لم يُحذف أي ملف.",
                        "Attempted: installed apps=" + scan.installedApps +
                            ", APK files=" + scan.appApksAttempted +
                            ", shared files=" + scan.sharedFilesAttempted +
                            ", stored APKs=" + scan.storedApksAttempted +
                            ", SHA-256 completed=" + scan.hashed +
                            ", files submitted to native engines=" + scan.nativeChecked +
                            " (installed=" + scan.nativeInstalledAttempts +
                            ", shared=" + scan.nativeSharedAttempts + ")" +
                            ", threat matches=" + scan.matches + ", harmless test samples=" + scan.testSamples +
                            ", files with incomplete inspection=" + scan.incomplete +
                            ", archive warnings=" + scan.structuralWarnings +
                            ".\n" +
                            "Completed engine checks: ClamAV ${scan.clamavCompleted} · YARA-X ${scan.yaraCompleted}.\n" +
                            (if (scan.truncated) "Scan ended before all accessible files were covered.\n" else "") +
                            (if (scan.inventoryIssues > 0) "Items that could not be listed: ${scan.inventoryIssues}.\n" else "") +
                            (if (scan.workerFailures > 0) "Scanner process failures: ${scan.workerFailures}.\n" else "") +
                            failureStages(false) +
                            (if (scan.yaraPaused) "YARA-X paused for this session after the process failed.\n" else "") +
                            (if (scan.nativePaused) "Native checks paused for this session. Hash checks continued.\n" else "") +
                            noteEn + "\n" + "Files per incomplete reason (a file may have several reasons):\n" +
                            scan.incompleteReasons.entries.sortedByDescending { it.value }.joinToString("\n") {
                                com.kanaf.alrasby.engine.ScanEvidenceText.reason(it.key, false) + " × " + it.value
                            } + "\n" + evidenceEn.take(2200) +
                            "\nAndroid exact-file rules and ESET/ReversingLabs Linux/ELF content rules. The same IOC across engines is one source. No match does not prove safety. Nothing deleted."
                    )
                },
                onFailure = { error -> KanafMessage(
                    "تعذر اكتمال فحص الجهاز: " + error.javaClass.simpleName,
                    "Device scan incomplete: " + error.javaClass.simpleName
                ) }
            )
        }
    }
    val sharedAccessLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        sharedStorageAccess = if (Build.VERSION.SDK_INT >= 30)
            Environment.isExternalStorageManager()
        else activity.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) ==
            PackageManager.PERMISSION_GRANTED
        scanAccessStatus = if (sharedStorageAccess)
            KanafMessage("تم منح إذن الملفات المشتركة.", "Shared-files access granted.")
        else KanafMessage("لم يُمنح إذن الملفات؛ سيُفحص ما يمكن الوصول إليه.",
            "Shared-files access denied; scanning only accessible applications.")
        if (scanOnFilesPermissionReturn) {
            scanOnFilesPermissionReturn = false
            startAutomaticDeviceScan()
        }
    }
    val oldStoragePermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        sharedStorageAccess = granted
        scanAccessStatus = if (granted)
            KanafMessage("تم منح إذن الملفات المشتركة.", "Shared-files access granted.")
        else KanafMessage("ستُفحص التطبيقات فقط.", "Only installed apps can be scanned.")
        if (scanOnFilesPermissionReturn) {
            scanOnFilesPermissionReturn = false
            startAutomaticDeviceScan()
        }
    }
    // A one-shot SAF grant, not a device-wide storage permission. No automatic deletion.
    val deviceScanPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { tree ->
        if (tree != null && !busy) {
            scopedScanCancellation.set(false)
            val session = scopedScanSession.incrementAndGet()
            scopedScanActive = true
            otherTaskBusy = true
            deviceScanStatus = KanafMessage(
                "جارٍ فحص الملفات التي أذنت بالوصول إليها، ومراجعة التطبيقات الظاهرة…",
                "Scanning the permitted folder and auditing visible installed apps…"
            )
            scope.launch {
                val attempted = withContext(Dispatchers.IO) {
                    runCatching {
                        val files = ScopedDeviceScan().scan(activity, tree) {
                            scopedScanCancellation.get() || scopedScanSession.get() != session
                        }
                        val apps = InstalledAppAudit().run(activity)
                        files to apps
                    }
                }
                if (scopedScanSession.get() != session) return@launch
                scopedScanActive = false
                deviceScanStatus = attempted.fold(
                    onSuccess = { (files, apps) ->
                        val findingsAr = files.findings.joinToString("\n") { finding ->
                            if (finding.kind == ScopedDeviceScan.FindingKind.STRUCTURAL_WARNING) {
                                finding.name + " — تحذير بنيوي: مسارات أرشيف غير آمنة؛ " +
                                    "ليس دليلًا على وجود برمجية خبيثة"
                            } else {
                                finding.name + " — " + finding.label + " (" +
                                    com.kanaf.alrasby.engine.ThreatFamily.label(finding.label, true) + ")"
                            }
                        }
                        val findingsEn = files.findings.joinToString("\n") { finding ->
                            if (finding.kind == ScopedDeviceScan.FindingKind.STRUCTURAL_WARNING) {
                                finding.name + " — Archive structure warning: unsafe paths; " +
                                    "not proof of malware"
                            } else {
                                finding.name + " — " + finding.label + " (" +
                                    com.kanaf.alrasby.engine.ThreatFamily.label(finding.label, false) + ")"
                            }
                        }
                        KanafMessage(
                            "فحص ضمن نطاق إذن المجلد، وليس فحصًا شاملًا للجهاز. ملفات تمت محاولة فحصها=" +
                                files.attempted + "، بدون تطابق معروف=" + files.scanned +
                                "، تطابقات توقيع=" + files.matched +
                                "، غير مكتمل=" + files.incomplete +
                                "، مؤشرات بنيوية=" + files.structuralWarnings +
                                "، حد الفحص=" + files.truncated + ".\n" +
                                "تطبيقات ظاهرة=${apps.candidates}، APK مفحوص=${apps.hashed}، " +
                                "تطابق=${apps.matched}، غير مكتمل=${apps.incomplete}، " +
                                "تجاوز الحد=${apps.truncated}.\n" +
                                findingsAr.take(2500) +
                                "\nلا يُحذف أي ملف. عدم التطابق لا يعني السلامة، والفحص غير المكتمل لا يُعد نظيفًا.",
                            "User-authorized folder only; not a full-device scan. Files attempted=" +
                                files.attempted + ", no known matches=" + files.scanned +
                                ", signature matches=" + files.matched +
                                ", incomplete=" + files.incomplete +
                                ", structural flags=" + files.structuralWarnings +
                                ", limits reached=" + files.truncated + ".\n" +
                                "Visible apps=${apps.candidates}, APKs hashed=${apps.hashed}, " +
                                "matches=${apps.matched}, incomplete=${apps.incomplete}, " +
                                "truncated=${apps.truncated}.\n" +
                                findingsEn.take(2500) +
                                "\nNo files were removed. No match is not proof of safety; incomplete is not clean."
                        )
                    },
                    onFailure = { failure -> KanafMessage(
                        "تعذر إكمال فحص الجهاز المسموح: " + failure.javaClass.simpleName,
                        "Permitted device scan incomplete: " + failure.javaClass.simpleName
                    ) }
                )
                otherTaskBusy = false
            }
        }
    }
    var vpnRequested by remember { mutableStateOf(KanafDnsVpnService.isRunning()) }
    var vpnStatus by remember { mutableStateOf(KanafMessage(
        "مرشح DNS غير مفعل إلا بموافقتك. يلزم VPN، ولا يمكن تشغيل VPN آخر معه.",
        "DNS filter is opt-in and requires VPN permission; it cannot run with another VPN."
    )) }
    var systemDns by remember { mutableStateOf(PrivateDnsCompatibility.read(activity)) }
    var privateDnsActionStatus by remember { mutableStateOf(KanafMessage.EMPTY) }
    var selectedDnsProvider by remember {
        mutableStateOf(DnsProviderStore.selected(activity))
    }
    var dnsQuickTileStatus by remember { mutableStateOf(KanafMessage.EMPTY) }
    var dnsCoverageStatus by remember { mutableStateOf(KanafMessage.EMPTY) }
    var dnsCoverageBusy by remember { mutableStateOf(false) }
    var dnsSwitching by remember { mutableStateOf(false) }
    var dnsStopping by remember { mutableStateOf(false) }
    var dnsSessionStats by remember {
        mutableStateOf(KanafMessage("العدادات متاحة أثناء تشغيل المرشح فقط.",
            "Counters are available only during an active DNS session."))
    }
    val dnsOperation = remember { AtomicLong(0) }

    fun refreshDnsCounters() {
        val counts = KanafDnsVpnService.sessionStats()
        dnsSessionStats = if (KanafDnsVpnService.isRunning()) KanafMessage(
            "منع=" + counts.blocked + "، تمرير=" + counts.forwarded +
                "، تعذّر=" + counts.failed + " · مؤقتة ولا تُحفظ",
            "Blocked=" + counts.blocked + ", forwarded=" + counts.forwarded +
                ", failed=" + counts.failed + " · session only"
        ) else KanafMessage(
            "المرشح متوقف، والعدادات غير محفوظة.",
            "Filtering is stopped; no session counters are retained."
        )
    }

    DisposableEffect(activity) {
        val owner = activity as? LifecycleOwner
        val results = WorkManager.getInstance(activity)
            .getWorkInfosForUniqueWorkLiveData(ProtectionControl.IMMEDIATE_CHECK)
        val observer = Observer<List<WorkInfo>> { work ->
            val latest = work.firstOrNull { !it.state.isFinished } ?: work.firstOrNull()
            protectionStatus = when (latest?.state) {
                WorkInfo.State.ENQUEUED, WorkInfo.State.BLOCKED ->
                    KanafMessage("فحص المجلد في انتظار التنفيذ.", "Folder scan queued.")
                WorkInfo.State.RUNNING ->
                    KanafMessage("جارٍ فحص المجلد المختار…", "Scanning selected folder…")
                WorkInfo.State.SUCCEEDED ->
                    KanafMessage.fromScheduledStatus(ProtectionControl.lastResult(activity))
                WorkInfo.State.FAILED ->
                    KanafMessage("تعذر إكمال مهمة فحص المجلد.", "Folder scan task failed.")
                WorkInfo.State.CANCELLED ->
                    KanafMessage("أُلغي فحص المجلد.", "Folder scan cancelled.")
                null -> protectionStatus
            }
        }
        if (owner != null) results.observe(owner, observer)
        onDispose { results.removeObserver(observer) }
    }

    // Android Settings may be changed outside Kanaf; refresh immediately on return.
    DisposableEffect(activity) {
        val owner = activity as? LifecycleOwner
        val listener = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) {
                // Preserve active user-requested work across navigation and transient stops.
                // Completed reports retain the existing clear-on-leave privacy behavior.
                if (!automaticScanActive && !manualScanActive &&
                    !scopedScanActive && !engineSelfTestActive) {
                    hasScanReport = false
                    lastManualUri = null
                    manualScanSummary = KanafMessage.EMPTY
                    status = KanafMessage(
                        "استخدم زر الفحص لمراجعة الجهاز", "Tap Scan to inspect your device"
                    )
                    selfTestStatus = KanafMessage.EMPTY
                    deviceScanStatus = deviceScanState.interruption?.description() ?: KanafMessage.EMPTY
                    scanHistoryArabic.clear()
                    scanHistoryEnglish.clear()
                }
            }
            if (event == Lifecycle.Event.ON_RESUME) {
                systemDns = PrivateDnsCompatibility.read(activity)
                vpnRequested = KanafDnsVpnService.isRunning()
                if (!vpnRequested) {
                    dnsSwitching = false
                    dnsStopping = false
                }
                selectedDnsProvider = KanafDnsVpnService.activeProvider()
                    ?: DnsProviderStore.selected(activity)
                refreshDnsCounters()
            }
        }
        owner?.lifecycle?.addObserver(listener)
        onDispose { owner?.lifecycle?.removeObserver(listener) }
    }

    fun startDnsFilter() {
        val operation = dnsOperation.incrementAndGet()
        systemDns = PrivateDnsCompatibility.read(activity)
        if (PrivateDnsToggle.decision(systemDns) ==
            PrivateDnsToggle.Decision.MANUAL_REQUIRED) {
            vpnRequested = false
            vpnStatus = KanafMessage(
                "DNS الخاص على مزوّد صارم. اختر «تلقائي» في إعدادات Android لتفعيل كنف دون ADB.",
                "Strict Android Private DNS is active. Select Automatic in Android settings to use Kanaf without ADB."
            )
            return
        }
        runCatching {
            val start = Intent(activity, KanafDnsVpnService::class.java)
                .setAction(KanafDnsVpnService.ACTION_START)
            activity.startForegroundService(start)
        }.onSuccess {
            vpnRequested = KanafDnsVpnService.isRunning()
            vpnStatus = KanafMessage(
                "جارٍ اختبار الاتصال المشفر بالمزوّد قبل تشغيل مرشح DNS…",
                "Checking encrypted DNS provider connectivity before activating filtering…"
            )
            scope.launch {
                repeat(36) {
                    delay(500)
                    if (dnsOperation.get() != operation) return@launch
                    if (KanafDnsVpnService.isRunning()) {
                        vpnRequested = true
                        selectedDnsProvider = KanafDnsVpnService.activeProvider()
                            ?: DnsProviderStore.selected(activity)
                        systemDns = PrivateDnsCompatibility.read(activity)
                        refreshDnsCounters()
                        vpnStatus = KanafMessage(
                            "مرشح DNS يعمل عبر الاتصال المشفّر المحدد.",
                            "DNS filtering active with the selected encrypted provider."
                        )
                        return@launch
                    }
                }
                if (dnsOperation.get() != operation) return@launch
                vpnRequested = KanafDnsVpnService.isRunning()
                systemDns = PrivateDnsCompatibility.read(activity)
                vpnStatus = KanafMessage(
                    "لم يبدأ مرشح DNS: المزوّد المحدد غير متاح أو يتعارض وضع DNS في النظام. لم يُفعّل VPN.",
                    "DNS filtering could not start: selected provider is unreachable or Android DNS settings conflict. VPN was not enabled."
                )
            }
        }.onFailure {
            vpnRequested = false
            vpnStatus = KanafMessage("تعذر بدء مرشح DNS: ", "Could not start DNS filter: ")
                .append(it.javaClass.simpleName)
        }
    }
    val vpnPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) startDnsFilter()
        else vpnStatus = KanafMessage(
            "لم تُمنح صلاحية VPN، والحجب غير مفعل.",
            "VPN permission was denied; blocking remains off."
        )
    }
    var vaultStatus by remember { mutableStateOf(KanafMessage.EMPTY) }
    var pendingRestoreId by rememberSaveable { mutableStateOf<String?>(null) }
    val inventory = remember { InstalledAppInventory() }
    var appEntries by remember { mutableStateOf<List<InstalledAppInventory.Entry>>(emptyList()) }
    var appsLoaded by remember { mutableStateOf(false) }
    var appsStatus by remember { mutableStateOf(KanafMessage.EMPTY) }
    var apkAuditStatus by remember { mutableStateOf(KanafMessage.EMPTY) }
    val vault = remember { EncryptedVault() }
    val vaultEntries = remember { mutableStateListOf<EncryptedVault.Entry>().also {
        it.addAll(runCatching { vault.list(activity) }.getOrDefault(emptyList()))
    } }
    fun reloadVault() {
        vaultEntries.clear()
        vaultEntries.addAll(vault.list(activity))
    }
    val quarantinePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null && !busy) {
            otherTaskBusy = true
            scope.launch {
                val result = withContext(Dispatchers.IO) {
                    runCatching { SafQuarantine(vault).isolateSelectedDocument(activity, uri) }
                }
                val outcome = result.getOrNull()
                vaultStatus = when (outcome) {
                    is SafQuarantine.Outcome.Moved -> KanafMessage(
                        "تم حذف المستند الأصلي بعد التحقق من النسخة المشفرة. احتفظ بمفتاح الجهاز لاستعادتها.",
                        "The selected original was deleted by Android after its encrypted copy was verified. Keep the device key for recovery."
                    )
                    is SafQuarantine.Outcome.CopyOnly -> KanafMessage(
                        "لم يُعزل الملف الأصلي؛ بقيت نسخة مشفرة فقط في الخزنة: ",
                        "Original was NOT isolated; encrypted copy only: "
                    ).append(outcome.reason)
                    is SafQuarantine.Outcome.Failed -> KanafMessage(
                        "لم ينجح الحفظ أو العزل: ", "Could not save or isolate: "
                    ).append(outcome.reason)
                    null -> KanafMessage("فشلت العملية قبل اكتمالها.", "Quarantine operation failed.")
                }
                reloadVault()
                otherTaskBusy = false
            }
        }
    }
    val vaultPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null && !busy) {
            otherTaskBusy = true
            scope.launch {
                val result = withContext(Dispatchers.IO) {
                    runCatching { vault.store(activity, uri) }
                }
                vaultStatus = if (result.isSuccess) {
                    reloadVault()
                    KanafMessage("حُفظت نسخة مشفرة داخل كنف، ولم يُحذف الملف الأصلي.",
                        "Encrypted copy saved in Kanaf; the original was not deleted.")
                } else {
                    KanafMessage("تعذر حفظ النسخة المشفرة: ", "Encrypted copy failed: ")
                        .append(result.exceptionOrNull()?.javaClass?.simpleName.orEmpty())
                }
                otherTaskBusy = false
            }
        }
    }
    val restorePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        val id = pendingRestoreId
        pendingRestoreId = null
        if (uri != null && id != null && !busy) {
            otherTaskBusy = true
            scope.launch {
                val result = withContext(Dispatchers.IO) {
                    runCatching { vault.restore(activity, id, uri) }
                }
                vaultStatus = if (result.isSuccess) {
                    KanafMessage("اكتملت الاستعادة؛ ما زالت النسخة المشفرة محفوظة في الخزنة.",
                        "Restored to your chosen document. The encrypted copy remains in the vault.")
                } else {
                    KanafMessage(
                        "فشلت الاستعادة. قد يكون الملف الناتج غير مكتمل؛ احذفه قبل المحاولة مجددًا: ",
                        "Restore failed. The output may be partial; delete it before retrying: "
                    ).append(result.exceptionOrNull()?.javaClass?.simpleName.orEmpty())
                }
                otherTaskBusy = false
            }
        }
    }
    var keepSessionHistory by rememberSaveable { mutableStateOf(true) }
    var signatures by remember {
        mutableStateOf(runCatching { SignatureRepository(activity).load() }.getOrNull())
    }
    val mlModel = remember { VerifiedLinearThreatModel.load(activity) as? VerifiedLinearThreatModel }
    val urlRiskModel = remember { KanafUrlAi.load(activity) }
    val apkAiStatus = mlModel?.let { model ->
        KanafMessage(
            "نموذج APK موقّع محمّل: " + model.modelVersion,
            "Signed APK advisory model: " + model.modelVersion
        )
    } ?: KanafMessage.EMPTY
    val urlAiStatus = if (urlRiskModel != null) KanafMessage(
        "تحليل روابط تجريبي فعّال محليًا بنموذج " + urlRiskModel.version +
            " مدرّب على بيانات PhiUSIIL التاريخية. النتائج تقديرية وليست تأكيدًا للسلامة.",
        "Experimental offline URL model " + urlRiskModel.version +
            " loaded from historical PhiUSIIL labels. Scores are advisory, not a safety guarantee."
    ) else KanafMessage(
        "نموذج روابط Kanaf AI التجريبي غير مضمّن في هذا البناء.",
        "Experimental Kanaf AI URL model is not included in this build."
    )
    val aiModelStatus = KanafMessage.combine(listOf(urlAiStatus, apkAiStatus))
    val trustedFeed = remember { ProductionFeedInstaller() }
    var feedStatus by remember { mutableStateOf(KanafMessage.EMPTY) }
    val rulesUpdater = remember { ThreatRuleUpdater() }
    fun refreshThreatRules() {
        if (busy) return
        val availability = rulesUpdater.availability()
        if (!availability.configured) {
            updateRulesStatus = KanafMessage(
                "تحديث قواعد الحماية غير متاح في هذا البناء: لم يُجهز الناشر مفتاح توقيع إنتاجيًا ورابط تحديث موثوقًا. تبقى قواعد المحركين المضمنة متاحة.",
                "Authenticated online updates unavailable in this build; bundled native rules remain available."
            )
            return
        }
        otherTaskBusy = true
        updateRulesStatus = KanafMessage("جارٍ التحقق من تحديث قاعدة التوقيعات الموقعة…",
            "Checking publisher-signed threat-rule update…")
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { rulesUpdater.update(activity) }
            }
            updateRulesStatus = result.fold(
                onSuccess = { version ->
                    signatures = runCatching { SignatureRepository(activity).load() }.getOrNull()
                    KanafMessage("تم التحقق من قاعدة التوقيعات الموقعة، الإصدار " + version,
                        "Authenticated threat feed is current, version " + version)
                },
                onFailure = { e -> KanafMessage(
                    "لم يُثبَّت تحديث. تعذّر التحقق أو لا يوجد إصدار أحدث: " +
                        e.javaClass.simpleName,
                    "No update installed; unavailable, not newer, or verification failed: " +
                        e.javaClass.simpleName
                ) }
            )
            otherTaskBusy = false
        }
    }
    val feedPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null && !busy) {
            otherTaskBusy = true
            scope.launch {
                val outcome = withContext(Dispatchers.IO) {
                    runCatching { trustedFeed.importSignedZip(activity, uri) }
                }
                if (outcome.isSuccess) {
                    signatures = runCatching { SignatureRepository(activity).load() }.getOrNull()
                    feedStatus = KanafMessage(
                        "تم تثبيت قاعدة توقيعات موثوقة؛ الإصدار ",
                        "Verified signature database installed, version "
                    ).append(outcome.getOrThrow().toString())
                } else {
                    feedStatus = KanafMessage(
                        "رُفض تحديث غير موثوق أو غير صالح: ",
                        "Untrusted or invalid feed rejected: "
                    ).append(outcome.exceptionOrNull()?.javaClass?.simpleName.orEmpty())
                }
                otherTaskBusy = false
            }
        }
    }
    fun scanSelectedFile(uri: Uri) {
        if (!busy) {
            val session = manualScanSession.incrementAndGet()
            manualScanActive = true
            lastManualUri = uri
            manualScanSummary = KanafMessage.EMPTY
            otherTaskBusy = true
            hasScanReport = false
            status = KanafMessage("جارٍ الفحص...", "Scanning…")
            scope.launch {
                val completed = withContext(Dispatchers.IO) {
                    try {
                        // Background updates may have replaced the database
                        // since this screen was composed. Read fresh trusted rows.
                        val activeSignatures = runCatching { SignatureRepository(activity).load() }.getOrNull()
                        val mime = activity.contentResolver.getType(uri).orEmpty()
                        val archive = mime == "application/zip" ||
                            mime == "application/x-zip-compressed" ||
                            mime == "application/vnd.android.package-archive"
                        val apk = mime == "application/vnd.android.package-archive" ||
                            uri.lastPathSegment.orEmpty().substringBefore('?').endsWith(".apk", ignoreCase = true)
                        var apkEvidence: ApkStructureInspector.Result? = null
                        val apkNote = if (apk) {
                            activity.contentResolver.openInputStream(uri)?.use { stream ->
                                when (val result = ApkStructureInspector().inspect(stream).also { apkEvidence = it }) {
                                    is ApkStructureInspector.Result.Complete ->
                                        KanafMessage(
                                            "APK: ملفات DEX=${result.summary.dexFiles}، مكتبات أصلية=${result.summary.nativeLibraries}، مسارات غير آمنة=${result.summary.unsafePaths}. تحليل بنية فقط.",
                                            "APK: DEX files=${result.summary.dexFiles}, native libraries=${result.summary.nativeLibraries}, unsafe paths=${result.summary.unsafePaths}. Structural analysis only; not malware detection."
                                        )
                                    is ApkStructureInspector.Result.Incomplete ->
                                        KanafMessage("فحص بنية APK غير مكتمل: ${result.reason}",
                                            "APK structure inspection incomplete: ${result.reason}")
                                }
                            } ?: KanafMessage("تعذر فتح ملف APK", "Could not open APK")
                        } else KanafMessage.EMPTY
                        var dexEvidence: DexHeaderInspector.Result? = null
                        val dexNote = if (apk) {
                            activity.contentResolver.openInputStream(uri)?.use { stream ->
                                when (val result = DexHeaderInspector().inspect(stream).also { dexEvidence = it }) {
                                    is DexHeaderInspector.Result.Complete ->
                                        KanafMessage("DEX: ${result.summary.dexFiles} ملف، رؤوس غير سليمة: ${result.summary.invalidHeaders}. تحليل بنية فقط.",
                                            "DEX: ${result.summary.dexFiles} files, invalid headers: ${result.summary.invalidHeaders}. Structural check only.")
                                    is DexHeaderInspector.Result.Incomplete ->
                                        KanafMessage("فحص DEX غير مكتمل: ${result.reason}", "DEX inspection incomplete: ${result.reason}")
                                }
                            } ?: KanafMessage("تعذر فتح APK لفحص DEX", "Could not open APK for DEX inspection")
                        } else KanafMessage.EMPTY
                        var zipEvidence: ZipInspector.Result? = null
                        val zipNote = if (archive || apk) {
                            activity.contentResolver.openInputStream(uri)?.use { stream ->
                                when (val inspected = ZipInspector().inspect(stream).also { zipEvidence = it }) {
                                    is ZipInspector.Result.Complete ->
                                        KanafMessage(
                                            "ZIP: ${inspected.summary.entries} مدخل، ${inspected.summary.bytesExpanded} بايت بعد الفك، مسارات غير آمنة: ${inspected.summary.unsafeNames}. تحليل بنية فقط.",
                                            "ZIP: ${inspected.summary.entries} entries, ${inspected.summary.bytesExpanded} uncompressed bytes, unsafe paths: ${inspected.summary.unsafeNames}. Structural check only."
                                        )
                                    is ZipInspector.Result.Incomplete ->
                                        KanafMessage("تحليل الأرشيف غير مكتمل: ${inspected.reason}", "ZIP inspection incomplete: ${inspected.reason}")
                                }
                            } ?: KanafMessage("تعذر فتح الأرشيف", "Could not open archive")
                        } else KanafMessage.EMPTY
                        run {
                            val scanResult = HashSignatureEngine(activeSignatures).scan({
                                activity.contentResolver.openInputStream(uri)
                            })
                            val native = NativeScannerBridge.scan(activity, uri)
                            val nativeReports = listOf(
                                EngineConsensus.Report("clamav", native.clamav),
                                EngineConsensus.Report("yara-x", native.yaraX)
                            )
                            val consensus = EngineConsensus.evaluate(
                                listOf(EngineConsensus.Report("kanaf-sha256", scanResult)) + nativeReports,
                                setOf("kanaf-sha256", "clamav", "yara-x")
                            )
                            val snapshotConflict = ScanEvidenceText.hasConflict(consensus)
                            val nativeNote = KanafMessage(
                                listOf(
                                    "نتائج كل محرك للملف. تُحسب البصمة المشتركة بين المحركات مصدرًا واحدًا.",
                                    ScanEvidenceText.nativeLabel("ClamAV", native.clamav, snapshotConflict),
                                    ScanEvidenceText.nativeLabel("YARA-X", native.yaraX, snapshotConflict)
                                ).joinToString("\n"),
                                listOf(
                                    "Per-engine results. A hash shared between engines counts as one source.",
                                    ScanEvidenceText.nativeLabel("ClamAV", native.clamav, snapshotConflict, arabic = false),
                                    ScanEvidenceText.nativeLabel("YARA-X", native.yaraX, snapshotConflict, arabic = false)
                                ).joinToString("\n")
                            )
                            val eicarOnly = consensus is EngineConsensus.Decision.Threat &&
                                consensus.detections.all {
                                    (it.verdict as AntivirusEngine.Verdict.Detected)
                                        .threatName.contains("eicar", ignoreCase = true)
                                }
                            val consensusNote = when (consensus) {
                                is EngineConsensus.Decision.Threat ->
                                    if (eicarOnly) KanafMessage(
                                        "نتيجة المحركات: نجح كشف عينة EICAR الاختبارية غير الضارة",
                                        "Engines: detected the harmless EICAR test sample"
                                    ) else KanafMessage(
                                        "نتيجة المحركات: رُصد تطابق تهديد معروف",
                                        "Engines: matched a known threat signature"
                                    )
                                is EngineConsensus.Decision.Inconclusive ->
                                    if (consensus.reason == "file-changed-between-engines") KanafMessage(
                                        "تحذير: تغير الملف بين قراءات المحركات؛ النتائج غير حاسمة ويجب إعادة الفحص.",
                                        "Warning: the file changed between engine reads. Results are inconclusive; rescan."
                                    ) else KanafMessage(
                                        "نتيجة المحركات: الفحص غير مكتمل",
                                        "Engines: scan incomplete"
                                    )
                                is EngineConsensus.Decision.NoKnownMatch -> KanafMessage(
                                    "نتيجة المحركات: لا تطابق معروف؛ السلامة غير مؤكدة",
                                    "Engines: no known match; file safety is NOT verified"
                                )
                            }
                            val verdict = KanafMessage(
                                ScanEvidenceText.hashLabel(
                                    scanResult, activeSignatures?.size ?: 0, snapshotConflict
                                ),
                                ScanEvidenceText.hashLabel(
                                    scanResult, activeSignatures?.size ?: 0, snapshotConflict, arabic = false
                                )
                            )
                            val modelResult = mlModel?.classify(
                                ThreatFeatureVector.from(apkEvidence, dexEvidence, zipEvidence)
                            )
                            val nativeDetection = nativeReports.firstNotNullOfOrNull {
                                (it.verdict as? AntivirusEngine.Verdict.Detected)?.threatName
                            }
                            // A match from a different file snapshot is not a confirmed
                            // match for the current selected file.
                            val trustedDetection = if (consensus is EngineConsensus.Decision.Threat) {
                                (scanResult as? AntivirusEngine.Verdict.Detected)?.threatName ?: nativeDetection
                            } else null
                            val assessment = ThreatEvidence.assess(
                                trustedDetection, apkEvidence, dexEvidence, zipEvidence
                            )
                            val structuralIncomplete = !ThreatEvidence.isStructuralInspectionComplete(
                                apkSelected = apk, archiveSelected = archive,
                                apk = apkEvidence, dex = dexEvidence, zip = zipEvidence
                            )
                            val assessmentNote = if (eicarOnly) {
                                KanafMessage(
                                    "عينة EICAR اختبارية غير ضارة؛ نجاح كشفها لا يثبت كشف برمجيات خبيثة حقيقية",
                                    "EICAR is a harmless test sample. Detecting it does not prove real-world malware coverage."
                                )
                            } else if (scanResult is AntivirusEngine.Verdict.Incomplete ||
                                activeSignatures == null || structuralIncomplete ||
                                consensus is EngineConsensus.Decision.Inconclusive) {
                                KanafMessage(
                                    "تقييم الأدلة: الفحص غير مكتمل أو قاعدة التوقيعات غير متاحة",
                                    "Evidence assessment: scan incomplete or signatures unavailable"
                                )
                            } else when (assessment.severity) {
                                ThreatEvidence.Severity.CONFIRMED -> KanafMessage(
                                    "تقييم الأدلة: تطابق توقيع معروف",
                                    "Evidence assessment: known signature matched"
                                )
                                ThreatEvidence.Severity.SUSPICIOUS -> KanafMessage(
                                    "تقييم الأدلة: مؤشرات بنيوية تستدعي المراجعة",
                                    "Evidence assessment: structural anomalies require review"
                                )
                                ThreatEvidence.Severity.INCONCLUSIVE -> KanafMessage(
                                    "تقييم الأدلة: تحليل غير مكتمل",
                                    "Evidence assessment: analysis incomplete"
                                )
                                ThreatEvidence.Severity.NO_KNOWN_MATCH -> KanafMessage(
                                    "تقييم الأدلة: لا توجد مؤشرات معروفة؛ السلامة غير مؤكدة",
                                    "Evidence assessment: no known indicators; safety not verified"
                                )
                            }
                            val journey = TrustJourney.build(
                                assessment,
                                scanCompleted = scanResult !is AntivirusEngine.Verdict.Incomplete && !structuralIncomplete && consensus !is EngineConsensus.Decision.Inconclusive,
                                signaturesAvailable = activeSignatures != null
                            )
                            val decisionNote = if (eicarOnly) {
                                KanafMessage(
                                    "اختبار EICAR ناجح؛ راجع حدود قواعد الكشف الحالية.",
                                    "EICAR test passed; review the current detection-rule limitations."
                                )
                            } else if (snapshotConflict) {
                                KanafMessage(
                                    "خطوتك التالية: أعد فحص الملف بعد التأكد من ثباته؛ لا تعتمد النتائج المتعارضة.",
                                    "Next step: rescan a stable file; do not trust contradictory evidence."
                                )
                            } else {
                                val englishNext = when (journey.action) {
                                    TrustJourney.Action.STOP_AND_VERIFY ->
                                        "Known signature match — do not install; verify the source and seek an additional scan."
                                    TrustJourney.Action.REVIEW_BEFORE_INSTALLING ->
                                        "Structural indicators require review — verify the publisher and avoid sensitive permissions."
                                    TrustJourney.Action.RETRY_SCAN ->
                                        "Incomplete analysis — address scan errors and retry; no safety claim can be made."
                                    TrustJourney.Action.VERIFY_SOURCE ->
                                        "No known match — verify the publisher and digital signature before installing."
                                }
                                KanafMessage("خطوتك التالية: ${journey.title} — ${journey.nextStep}",
                                    "Next step: $englishNext")
                            }
                            val aiNote = (modelResult as? ThreatModel.Prediction.Scored)?.let { score ->
                                KanafMessage(
                                    "درجة النموذج الموقّع الاستشارية: ${score.riskProbability}",
                                    "Signed model advisory score: ${score.riskProbability}"
                                )
                            } ?: KanafMessage.EMPTY
                            KanafMessage.combine(listOf(
                                decisionNote, assessmentNote, consensusNote,
                                nativeNote, aiNote, verdict, apkNote, dexNote, zipNote
                            ))
                        }
                    } catch (e: Exception) {
                        KanafMessage("تعذر إكمال الفحص: ${e.javaClass.simpleName}",
                            "Could not complete scan: ${e.javaClass.simpleName}")
                    }
                }
                if (manualScanSession.get() != session) return@launch
                manualScanActive = false
                status = completed
                manualScanSummary = KanafMessage(
                    completed.ar.lineSequence().firstOrNull().orEmpty(),
                    completed.en.lineSequence().firstOrNull().orEmpty()
                )
                hasScanReport = true
                // Only a bounded, non-persistent summary; never retain file names or contents.
                com.kanaf.alrasby.engine.SessionHistoryPolicy.record(
                    scanHistoryArabic, completed.ar, keepSessionHistory
                )
                com.kanaf.alrasby.engine.SessionHistoryPolicy.record(
                    scanHistoryEnglish, completed.en, keepSessionHistory
                )
                otherTaskBusy = false
            }
        }
    }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scanSelectedFile(uri)
    }
    LaunchedEffect(sharedFile, shareRequest) {
        sharedFile?.let { scanSelectedFile(it) }
    }
    if (askFilesBeforeScan) {
        AlertDialog(
            onDismissRequest = { askFilesBeforeScan = false },
            title = { Text(localized("فحص الملفات", "Scan shared files")) },
            text = { Text(localized(
                "يمكنك فحص التطبيقات فورًا دون أذونات إضافية. لتضمين التنزيلات والصور والملفات المشتركة، يحتاج كنف إلى موافقة واحدة من إعدادات Android. لا يصل إلى بيانات التطبيقات الخاصة ولا يحذف شيئًا.",
                "You can scan installed apps without extra permissions. To include downloads, photos and shared files, allow Android's one-time file access. Private app data remains protected and nothing is deleted."
            ), style = MaterialTheme.typography.kanafDescription) },
            confirmButton = {
                TextButton(onClick = {
                    askFilesBeforeScan = false
                    scanOnFilesPermissionReturn = true
                    if (Build.VERSION.SDK_INT >= 30) {
                        val request = Intent(
                            Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                            Uri.parse("package:" + activity.packageName)
                        )
                        runCatching { sharedAccessLauncher.launch(request) }
                            .onFailure { sharedAccessLauncher.launch(
                                Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)) }
                    } else oldStoragePermission.launch(Manifest.permission.READ_EXTERNAL_STORAGE)
                }, modifier = Modifier.testTag("grant_files_for_auto_scan")) {
                    Text(localized("السماح ثم الفحص", "Allow and scan"))
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    askFilesBeforeScan = false
                    startAutomaticDeviceScan()
                }, modifier = Modifier.testTag("scan_apps_only")) {
                    Text(localized("فحص التطبيقات فقط", "Apps only"))
                }
            }
        )
    }
    KanafGlassHome(
        busy = busy,
        sharedText = sharedText,
        sharedFileRequest = if (sharedFile != null) shareRequest else null,
        uiLanguage = uiLanguage,
        hiddenSections = hiddenSections,
        onLanguageChange = { selected ->
            if (selected != uiLanguage) {
                runCatching { uiPreferences.setLanguage(selected) }.onSuccess {
                    uiLanguage = selected
                }.onFailure {
                    android.widget.Toast.makeText(activity,
                        localized("تعذر حفظ اللغة", "Could not save language preference"),
                        android.widget.Toast.LENGTH_SHORT).show()
                }
            }
        },
        onSectionVisibilityChanged = { section, visible ->
            runCatching { uiPreferences.setSectionVisible(section, visible) }.onSuccess {
                hiddenSections = uiPreferences.hiddenSections()
            }.onFailure {
                android.widget.Toast.makeText(activity,
                    localized("تعذر حفظ إعداد القسم", "Could not save navigation preference"),
                    android.widget.Toast.LENGTH_SHORT).show()
            }
        },
        scanHistory = if (arabic) scanHistoryArabic else scanHistoryEnglish,
        watchNewApps = watchNewApps,
        periodicChecks = periodicChecks,
        protectionStatus = protectionStatus.displayed(uiLanguage),
        onWatchNewApps = { enabled ->
            ProtectionControl.setInstallWatch(activity, enabled)
            watchNewApps = enabled
            protectionStatus = if (enabled)
                KanafMessage("فُعّلت تنبيهات تثبيت التطبيقات للمراجعة اليدوية فقط.",
                    "Opt-in install/update scanning enabled; Android scheduling restrictions apply.")
            else KanafMessage("تم إيقاف تنبيهات التثبيت.", "Install review alerts disabled.")
            if (enabled && Build.VERSION.SDK_INT >= 33 &&
                activity.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
                PackageManager.PERMISSION_GRANTED) {
                notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        },
        onChangePeriodic = { enabled ->
            if (enabled) {
                folderPicker.launch(null)
            } else {
                ProtectionControl.disableTreeChecks(activity)
                periodicChecks = false
                protectionStatus = KanafMessage(
                    "أُلغي الفحص الدوري وأُزيل إذن المجلد المختار.",
                    "Scheduled checks cancelled and selected folder access removed."
                )
            }
        },
        onRunScopedCheck = {
            if (periodicChecks && !busy) {
                ProtectionControl.checkNow(activity)
                protectionStatus = KanafMessage(
                    "طُلب فحص المجلد، وسيُنفّذ عندما يسمح نظام أندرويد.",
                    "Folder check requested; Android will execute it when allowed."
                )
            }
        },
        onRefreshProtection = {
            protectionStatus = KanafMessage.fromScheduledStatus(
                ProtectionControl.lastResult(activity)
            )
        },
        hasScanReport = hasScanReport,
        canImportSignedFeed = trustedFeed.configured(),
        signedFeedStatus = feedStatus.displayed(uiLanguage),
        onImportSignedFeed = { if (!busy && trustedFeed.configured())
            feedPicker.launch(arrayOf("application/zip", "application/octet-stream")) },
        onShareReport = {
            if ((hasScanReport || deviceScanStatus.ar.isNotBlank()) && !busy) {
                val currentReport = if (deviceScanStatus.ar.isNotBlank()) deviceScanStatus.displayed(uiLanguage)
                    else status.displayed(uiLanguage)
                scope.launch {
                    val report = withContext(Dispatchers.IO) {
                        runCatching {
                            "Kanaf " + BuildConfig.VERSION_NAME + " (" + BuildConfig.VERSION_CODE + ")\n" +
                                java.util.Date().toString() + "\n" +
                                com.kanaf.alrasby.engine.ProtectionHealth.describe(activity, arabic, includeDiagnostics = true) +
                                "\n\n" + currentReport
                        }
                    }
                    report.onSuccess { text ->
                        runCatching {
                            activity.startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_TEXT, text.take(20_000))
                            }, localized("مشاركة تقرير الفحص", "Share scan report")))
                        }.onFailure { vaultStatus = KanafMessage("تعذر فتح واجهة المشاركة", "Sharing is unavailable") }
                    }.onFailure { vaultStatus = KanafMessage("تعذر تجهيز التقرير", "Could not prepare report") }
                }
            }
        },
        vaultItems = vaultEntries,
        vaultStatus = vaultStatus.displayed(uiLanguage),
        installedApps = appEntries,
        appsLoaded = appsLoaded,
        appsStatus = appsStatus.displayed(uiLanguage),
        onLoadApps = {
            if (!busy) {
                otherTaskBusy = true
                scope.launch {
                    val found = withContext(Dispatchers.IO) {
                        runCatching { inventory.load(activity) }
                    }
                    if (found.isSuccess) {
                        appEntries = found.getOrThrow()
                        appsLoaded = true
                        appsStatus = KanafMessage(
                            "المعروض هو التطبيقات القابلة للتشغيل الظاهرة لكنف فقط؛ لم تُفحص بحثًا عن البرمجيات الخبيثة.",
                            "Only launchable apps visible to Kanaf are listed; no malware detection was performed."
                        )
                    } else {
                        appsStatus = KanafMessage("تعذر قراءة التطبيقات الظاهرة", "Could not list visible apps")
                    }
                    otherTaskBusy = false
                }
            }
        },
        apkAuditStatus = apkAuditStatus.displayed(uiLanguage),
        onAuditApps = {
            if (!busy) {
                otherTaskBusy = true
                apkAuditStatus = KanafMessage("جارٍ فحص ملفات APK الظاهرة...",
                    "Auditing visible APK files...")
                scope.launch {
                    val attempt = withContext(Dispatchers.IO) {
                        runCatching { InstalledAppAudit().run(activity) }
                    }
                    apkAuditStatus = if (attempt.isSuccess) {
                        val report = attempt.getOrThrow()
                        KanafMessage(
                            "مراجعة APK محدودة (ليست فحصًا شاملًا): المتاحة=${report.candidates}، " +
                                "لا تطابق=${report.hashed}، تطابقات=${report.matched}، " +
                                "مؤشرات بنيوية=${report.suspiciousStructure}، غير مكتمل=${report.incomplete}، " +
                                "تجاوز الحد=${report.truncated}. لا يمكن إثبات السلامة بهذه النتيجة.",
                            "Limited APK audit (not whole-device scanning): available=${report.candidates}, " +
                                "no matches=${report.hashed}, matches=${report.matched}, " +
                                "structural flags=${report.suspiciousStructure}, incomplete=${report.incomplete}, " +
                                "truncated=${report.truncated}. These results cannot certify safety."
                        )
                    } else KanafMessage(
                        "تعذرت مراجعة APK: ", "APK audit failed: "
                    ).append(attempt.exceptionOrNull()?.javaClass?.simpleName.orEmpty())
                    otherTaskBusy = false
                }
            }
        },
        onOpenAppDetails = { packageName ->
            runCatching {
                activity.startActivity(inventory.settingsIntent(packageName))
            }.onFailure {
                appsStatus = KanafMessage("تعذر فتح صفحة التطبيق", "Could not open Android app details")
            }
        },
        onAddToVault = { if (!busy) vaultPicker.launch(arrayOf("*/*")) },
        onQuarantineDocument = { if (!busy) quarantinePicker.launch(arrayOf("*/*")) },
        onRestoreVault = { id ->
            if (!busy) {
                pendingRestoreId = id
                restorePicker.launch("Kanaf-Restored-${id.take(8)}.bin")
            }
        },
        onDeleteVault = { id ->
            if (!busy) {
                otherTaskBusy = true
                scope.launch {
                    val removed = withContext(Dispatchers.IO) {
                        runCatching { vault.delete(activity, id) }.getOrDefault(false)
                    }
                    reloadVault()
                    vaultStatus = if (removed) KanafMessage(
                        "حُذفت النسخة المشفرة داخل كنف فقط.",
                        "Only the encrypted copy in Kanaf was deleted."
                    ) else KanafMessage(
                        "تعذر حذف النسخة؛ تحقق من التخزين.",
                        "Could not delete the vault copy; check storage."
                    )
                    otherTaskBusy = false
                }
            }
        },
        keepSessionHistory = keepSessionHistory,
        onSessionHistoryChanged = { enabled ->
            keepSessionHistory = enabled
            com.kanaf.alrasby.engine.SessionHistoryPolicy.onEnabledChanged(scanHistoryArabic, enabled)
            com.kanaf.alrasby.engine.SessionHistoryPolicy.onEnabledChanged(scanHistoryEnglish, enabled)
        },
        onClearHistory = {
            scanHistoryArabic.clear()
            scanHistoryEnglish.clear()
        },
        selfTestStatus = selfTestStatus.displayed(uiLanguage),
        aiModelStatus = aiModelStatus.displayed(uiLanguage),
        urlRiskModel = urlRiskModel,
        onTestEngines = {
            if (!busy) {
                val session = selfTestSession.incrementAndGet()
                engineSelfTestActive = true
                otherTaskBusy = true
                scope.launch {
                    val completed = withContext(Dispatchers.IO) {
                        val testResult = NativeScannerBridge.selfTest(activity)
                        fun label(name: String, verdict: AntivirusEngine.Verdict,
                                  arabic: Boolean): String =
                            if (arabic) when (verdict) {
                                is AntivirusEngine.Verdict.Detected ->
                                    "$name: نجح اكتشاف عينة EICAR الاختبارية"
                                is AntivirusEngine.Verdict.NoKnownMatch ->
                                    "$name: فشل اكتشاف عينة EICAR"
                                is AntivirusEngine.Verdict.Incomplete ->
                                    "$name: اختبار غير مكتمل (${verdict.reason})"
                            } else when (verdict) {
                                is AntivirusEngine.Verdict.Detected ->
                                    "$name: Detected the EICAR test sample"
                                is AntivirusEngine.Verdict.NoKnownMatch ->
                                    "$name: Failed to detect EICAR"
                                is AntivirusEngine.Verdict.Incomplete ->
                                    "$name: Test incomplete (${verdict.reason})"
                            }
                        KanafMessage(
                            listOf(
                                "اختبار الكشف عبر المحركات الأصلية — عينة EICAR غير الضارة:",
                                label("ClamAV", testResult.clamav, true),
                                label("YARA-X", testResult.yaraX, true)
                            ).joinToString("\n"),
                            listOf(
                                "Native engine detection test — harmless EICAR sample:",
                                label("ClamAV", testResult.clamav, false),
                                label("YARA-X", testResult.yaraX, false)
                            ).joinToString("\n")
                        )
                    }
                    if (selfTestSession.get() != session) return@launch
                    engineSelfTestActive = false
                    selfTestStatus = completed
                    otherTaskBusy = false
                }
            }
        },
        status = status.displayed(uiLanguage),
        onPickFile = { picker.launch(arrayOf("*/*")) },
        deviceScanStatus = deviceScanStatus.displayed(uiLanguage),
        onDeviceScan = {
            sharedStorageAccess = if (Build.VERSION.SDK_INT >= 30)
                Environment.isExternalStorageManager()
            else activity.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) ==
                PackageManager.PERMISSION_GRANTED
            if (sharedStorageAccess) startAutomaticDeviceScan()
            else askFilesBeforeScan = true
        },
        onScanChosenFolder = { if (!busy) deviceScanPicker.launch(null) },
        fileScanSummary = localized(manualScanSummary.ar, manualScanSummary.en),
        onRetryFileScan = lastManualUri?.let { uri -> { scanSelectedFile(uri) } },
        onStopDeviceScan = deviceScan::stop,
        autoScanProgress = autoScanProgress,
        sharedStorageAccess = sharedStorageAccess,
        scanAccessStatus = scanAccessStatus.displayed(uiLanguage),
        onRequestSharedStorage = {
            if (Build.VERSION.SDK_INT >= 30) {
                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                    Uri.parse("package:" + activity.packageName))
                runCatching { sharedAccessLauncher.launch(intent) }
                    .onFailure {
                        sharedAccessLauncher.launch(
                            Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                    }
            } else {
                oldStoragePermission.launch(Manifest.permission.READ_EXTERNAL_STORAGE)
            }
        },
        rulesUpdateStatus = updateRulesStatus.displayed(uiLanguage),
        onUpdateThreatRules = { refreshThreatRules() },
        vpnRequested = vpnRequested,
        vpnStatus = vpnStatus.displayed(uiLanguage),
        privateDnsAvailable = Build.VERSION.SDK_INT >= 28,
        privateDnsStatus = when (systemDns.mode) {
            PrivateDnsCompatibility.Mode.OFF ->
                localized("DNS الخاص: متوقف في النظام", "Android Private DNS: Off")
            PrivateDnsCompatibility.Mode.AUTOMATIC ->
                localized("DNS الخاص: تلقائي في النظام", "Android Private DNS: Automatic")
            PrivateDnsCompatibility.Mode.PROVIDER ->
                localized("DNS الخاص في النظام: ", "Android Private DNS: ") +
                    systemDns.provider.orEmpty().ifBlank { "Provider configured" }
            PrivateDnsCompatibility.Mode.UNKNOWN ->
                localized("تعذر معرفة وضع DNS الخاص من النظام", "Android Private DNS status unavailable")
        },
        privateDnsCompatible = systemDns.allowsLocalVpn,
        privateDnsActionStatus = privateDnsActionStatus.displayed(uiLanguage),
        selectedDnsProvider = selectedDnsProvider,
        onSelectDnsProvider = { provider ->
            if (dnsStopping) {
                vpnStatus = KanafMessage(
                    "يجري فصل اتصال DNS، انتظر تأكيد الإيقاف.",
                    "DNS is disconnecting; wait for the stop to complete."
                )
            } else if (KanafDnsVpnService.isRunning()) {
                if (KanafDnsVpnService.isSwitching()) {
                    vpnStatus = KanafMessage(
                        "يجري التحقق من المزوّد الجديد، حاول بعد اكتمال التبديل.",
                        "The new DNS provider is being verified; finish this switch first."
                    )
                } else if (KanafDnsVpnService.activeProvider() != provider) {
                    val operation = dnsOperation.incrementAndGet()
                    dnsSwitching = true
                    vpnStatus = KanafMessage(
                        "جارٍ التحقق من المزوّد المشفّر الجديد مع إبقاء الاتصال الحالي.",
                        "Verifying the new encrypted provider while keeping DNS connected."
                    )
                    val change = Intent(activity, KanafDnsVpnService::class.java)
                        .setAction(KanafDnsVpnService.ACTION_CHANGE_PROVIDER)
                        .putExtra(KanafDnsVpnService.EXTRA_PROVIDER, provider)
                    runCatching { activity.startService(change) }.onSuccess {
                        scope.launch {
                            try {
                            repeat(52) {
                                delay(250)
                                if (dnsOperation.get() != operation) return@launch
                                if (KanafDnsVpnService.activeProvider() == provider) {
                                    selectedDnsProvider = DnsProviderStore.selected(activity)
                                    vpnStatus = KanafMessage(
                                        "اكتمل التحويل للمزوّد المشفّر الجديد دون قطع VPN.",
                                        "Encrypted DNS provider switched without dropping VPN."
                                    )
                                    refreshDnsCounters()
                                    return@launch
                                }
                                if (!KanafDnsVpnService.isRunning()) {
                                    vpnRequested = false
                                    vpnStatus = KanafMessage(
                                        "انقطع اتصال Kanaf DNS أثناء التبديل.",
                                        "Kanaf DNS disconnected during provider change."
                                    )
                                    return@launch
                                }
                                if (!KanafDnsVpnService.isSwitching() &&
                                    KanafDnsVpnService.lastSwitchError() != null) {
                                    vpnStatus = KanafMessage(
                                        "تعذّر الوصول إلى المزوّد الجديد، بقي القديم فعّالًا.",
                                        "New provider check failed; the previous provider remains active."
                                    )
                                    return@launch
                                }
                            }
                            vpnStatus = KanafMessage(
                                "لم يتأكد التبديل. تحقق من الاتصال وأعد المحاولة.",
                                "Provider change not confirmed. Check the connection and retry."
                            )
                            } finally {
                                if (dnsOperation.get() == operation) dnsSwitching = false
                            }
                        }
                    }.onFailure {
                        dnsSwitching = false
                        vpnStatus = KanafMessage(
                            "تعذر إرسال طلب تغيير المزوّد.",
                            "Could not request a DNS provider change."
                        )
                    }
                }
            } else if (KanafDnsVpnService.isStarting()) {
                vpnStatus = KanafMessage(
                    "يجري بدء DNS، انتظر اكتمال الاتصال قبل تغيير المزوّد.",
                    "DNS is starting; change the provider after connection."
                )
            } else if (DnsProviderStore.choose(activity, provider)) {
                selectedDnsProvider = provider
                vpnStatus = KanafMessage(
                    "تم اختيار المزوّد. سيُستخدم عند تفعيل كنف.",
                    "Provider selected; it will be used when Kanaf starts."
                )
            } else {
                vpnStatus = KanafMessage("تعذّر حفظ المزوّد.", "Could not save DNS provider.")
            }
        },
        dnsSessionStats = dnsSessionStats.displayed(uiLanguage),
        dnsBusy = dnsStopping || dnsSwitching || KanafDnsVpnService.isStarting(),
        dnsCoverageStatus = dnsCoverageStatus.displayed(uiLanguage),
        onRefreshDnsStats = { refreshDnsCounters() },
        onCheckDnsCoverage = {
            if (!dnsCoverageBusy) {
                dnsCoverageBusy = true
                dnsCoverageStatus = KanafMessage(
                    "جارٍ اختبار اتصال DNS المشفر والتغطية المتاحة...",
                    "Checking encrypted DNS reachability and available coverage..."
                )
                val provider = KanafDnsVpnService.activeProvider()
                    ?: DnsProviderStore.selected(activity)
                scope.launch {
                    val result = withContext(Dispatchers.IO) {
                        runCatching { DnsCoverageProbe.check(activity, provider) }
                    }
                    dnsCoverageStatus = result.fold(onSuccess = { report ->
                        val reachableAr = if (report.upstreamReachable) "متاح" else "غير متاح"
                        val reachableEn = if (report.upstreamReachable) "reachable" else "unreachable"
                        val activeAr = if (report.filteringActive) "نشط" else "متوقف"
                        val activeEn = if (report.filteringActive) "active" else "stopped"
                        val ipv6Ar = if (report.ipv6DnsConfigured)
                            "الشبكة تستخدم DNS IPv6. كنف يدعم استعلامات DNS الواردة إلى عنوانه IPv6، لكن بعض التطبيقات قد تتجاوزه."
                        else "لم يُرصد خادم DNS IPv6 خارجي؛ لا يمكن ضمان عدم التجاوز."
                        val ipv6En = if (report.ipv6DnsConfigured)
                            "Underlying IPv6 DNS exists. Kanaf handles queries to its own IPv6 DNS address, but apps may bypass it."
                        else "No external IPv6 DNS was visible; full leak prevention is not proven."
                        KanafMessage(
                            "الخادم المشفر: " + reachableAr + " · مرشح كنف: " + activeAr +
                                ". " + ipv6Ar + " لا يشمل هذا الفحص DNS المشفّر داخل التطبيقات.",
                            "Encrypted upstream: " + reachableEn + " · Kanaf: " + activeEn +
                                ". " + ipv6En + " App-owned encrypted DNS cannot be tested here."
                        )
                    }, onFailure = { error ->
                        KanafMessage(
                            "تعذّر فحص الاتصال: " + error.javaClass.simpleName,
                            "Connection check unavailable: " + error.javaClass.simpleName
                        )
                    })
                    dnsCoverageBusy = false
                    refreshDnsCounters()
                }
            }
        },
        dnsQuickTileStatus = dnsQuickTileStatus.displayed(uiLanguage),
        onAddDnsQuickTile = {
            if (Build.VERSION.SDK_INT >= 33) {
                runCatching {
                    val manager = activity.getSystemService(StatusBarManager::class.java)
                    manager.requestAddTileService(
                        ComponentName(activity, KanafDnsTileService::class.java),
                        "Kanaf DNS",
                        Icon.createWithResource(activity, R.drawable.kanaf_status_icon),
                        activity.mainExecutor
                    ) { code ->
                        dnsQuickTileStatus = when (code) {
                            StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ADDED ->
                                KanafMessage("تمت إضافة مربع Kanaf DNS.",
                                    "Kanaf DNS tile added.")
                            StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ALREADY_ADDED ->
                                KanafMessage("مربع Kanaf DNS موجود مسبقًا.",
                                    "Kanaf DNS tile already exists.")
                            else -> KanafMessage(
                                "لم تتم إضافة المربع. استخدم تحرير الإعدادات السريعة لإضافته يدويًا.",
                                "Tile was not added. Use Quick Settings edit to add it manually."
                            )
                        }
                    }
                }.onFailure {
                    dnsQuickTileStatus = KanafMessage(
                        "أضف Kanaf DNS يدويًا من تحرير الإعدادات السريعة.",
                        "Add Kanaf DNS manually from Quick Settings edit."
                    )
                }
            } else {
                dnsQuickTileStatus = KanafMessage(
                    "افتح لوحة الإعدادات السريعة واضغط تحرير، ثم أضف مربع Kanaf DNS.",
                    "Open Quick Settings, choose Edit and add the Kanaf DNS tile."
                )
            }
        },
        onOpenPrivateDnsSettings = {
            if (!PrivateDnsSettingsNavigator.open(activity)) {
                privateDnsActionStatus = KanafMessage(
                    "تعذر فتح إعدادات الشبكة في هذا الهاتف.",
                    "Could not open Android network settings on this device."
                )
            }
        },
        onChoosePrivateDns = { provider ->
            if (provider != null && !PrivateDnsCompatibility.validHostname(provider)) {
                privateDnsActionStatus = KanafMessage(
                    "اسم المزوّد غير صالح. أدخل اسم نطاق DNS دون https:// أو عنوان IP.",
                    "Invalid provider hostname. Enter a DNS hostname, not an HTTPS URL or IP."
                )
            } else {
                val copied = provider?.let { host ->
                    runCatching {
                        val clipboard = activity.getSystemService(Context.CLIPBOARD_SERVICE)
                            as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText(
                            "Private DNS hostname", host.trim()))
                    }.isSuccess
                } ?: true
                privateDnsActionStatus = if (provider != null && copied)
                    KanafMessage(
                        "نُسخ اسم DNS: " + provider.trim() +
                            ". افتح إعدادات Android واختر «اسم مضيف مزوّد DNS الخاص» ثم الصقه.",
                        "Copied DNS host: " + provider.trim() +
                            ". In Android Private DNS choose Provider hostname and paste it."
                    )
                else if (provider == null)
                    KanafMessage(
                        "اختر «إيقاف» أو «تلقائي» من نافذة إعدادات Android. لا يغيّر كنف إعدادات النظام تلقائيًا.",
                        "Choose Off or Automatic in Android Settings. Kanaf cannot change system DNS automatically."
                    )
                else KanafMessage("تعذر نسخ اسم مزوّد DNS", "Could not copy DNS hostname")
                if (copied && !PrivateDnsSettingsNavigator.open(activity)) {
                    privateDnsActionStatus = KanafMessage(
                        "افتح إعدادات اتصال الهاتف يدويًا.",
                        "Open Android connection settings manually."
                    )
                }
            }
        },
        onVpnToggle = { enabled ->
            if (!enabled) {
                val operation = dnsOperation.incrementAndGet()
                dnsSwitching = false
                dnsStopping = true
                val stop = Intent(activity, KanafDnsVpnService::class.java)
                    .setAction(KanafDnsVpnService.ACTION_STOP)
                runCatching { activity.startService(stop) }
                    .onFailure { activity.stopService(
                        Intent(activity, KanafDnsVpnService::class.java)) }
                vpnStatus = KanafMessage(
                    "جارٍ إغلاق واجهة VPN الفعلية. قد يبقى ملف Kanaf محفوظًا في إعدادات أندرويد دون اتصال.",
                    "Disconnecting the VPN interface. Android may still show a saved Kanaf VPN profile when disconnected."
                )
                scope.launch {
                    repeat(24) {
                        delay(250)
                        if (dnsOperation.get() != operation) return@launch
                        if (!KanafDnsVpnService.isRunning() &&
                            !KanafDnsVpnService.isStarting()) {
                            dnsStopping = false
                            vpnRequested = false
                            refreshDnsCounters()
                            vpnStatus = KanafMessage(
                                "توقف Kanaf DNS وانقطع نفق VPN. قد يبقى اسم ملف Kanaf محفوظًا في إعدادات الهاتف.",
                                "Kanaf DNS VPN tunnel disconnected. The saved Android VPN profile may remain listed."
                            )
                            return@launch
                        }
                    }
                    if (dnsOperation.get() != operation) return@launch
                    dnsStopping = false
                    vpnRequested = KanafDnsVpnService.isRunning()
                    vpnStatus = KanafMessage(
                        "تعذر تأكيد فصل VPN. افتح إعدادات VPN في أندرويد للتحقق.",
                        "VPN disconnection could not be confirmed. Check Android VPN settings."
                    )
                }
            } else if (dnsStopping) {
                vpnStatus = KanafMessage(
                    "جارٍ إيقاف VPN، انتظر اكتمال الفصل قبل إعادة التشغيل.",
                    "VPN is disconnecting; wait for confirmation before restarting."
                )
            } else {
                systemDns = PrivateDnsCompatibility.read(activity)
                if (PrivateDnsToggle.decision(systemDns) ==
                    PrivateDnsToggle.Decision.MANUAL_REQUIRED) {
                    vpnRequested = false
                    vpnStatus = KanafMessage(
                        "DNS الخاص يستخدم مزوّدًا صارمًا. اختر «تلقائي» في إعدادات الهاتف دون ADB.",
                        "Private DNS is set to a strict provider. Choose Automatic in phone settings; no ADB required."
                    )
                } else {
                    val approval = VpnService.prepare(activity)
                    if (approval == null) startDnsFilter() else vpnPermission.launch(approval)
                }
            }
        },
        onVpnRefresh = {
            PrivateDnsToggle.recoverIfStopped(activity)
            systemDns = PrivateDnsCompatibility.read(activity)
            vpnRequested = KanafDnsVpnService.isRunning()
            selectedDnsProvider = KanafDnsVpnService.activeProvider()
                ?: DnsProviderStore.selected(activity)
            refreshDnsCounters()
            vpnStatus = if (vpnRequested) KanafMessage(
                "مرشح DNS المحلي يعمل (تغطية محدودة).",
                "Local DNS filter is running (limited coverage)."
            ) else KanafMessage(
                "مرشح DNS غير نشط. قد يبقى ملف VPN محفوظًا في أندرويد.",
                "DNS filter inactive; Android may retain its saved VPN profile."
            )
        },
        onOpenSystemApps = {
            runCatching {
                activity.startActivity(Intent(android.provider.Settings.ACTION_APPLICATION_SETTINGS))
            }.onFailure {
                android.widget.Toast.makeText(activity,
                    localized("تعذر فتح إعدادات التطبيقات", "Could not open Android app settings"),
                    android.widget.Toast.LENGTH_SHORT).show()
            }
        },
        onOpenWebsite = {
            runCatching {
                activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://nabdhserv.net")))
            }.onFailure {
                android.widget.Toast.makeText(activity,
                    localized("تعذر فتح المتصفح", "Could not open the browser"),
                    android.widget.Toast.LENGTH_SHORT).show()
            }
        }
    )
}
