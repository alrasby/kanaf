package com.kanaf.alrasby

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.Manifest
import android.os.Build
import android.content.pm.PackageManager
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.kanaf.alrasby.engine.ThreatFeatureVector
import com.kanaf.alrasby.engine.UnavailableThreatModel
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
import com.kanaf.alrasby.engine.ScopedFileCheckWorker
import com.kanaf.alrasby.engine.SafQuarantine
import com.kanaf.alrasby.engine.ProductionFeedInstaller
import com.kanaf.alrasby.engine.InstalledAppInventory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private var incomingSharedText by mutableStateOf<String?>(null)

    private fun extractSharedText(from: Intent?): String? {
        if (from?.action != Intent.ACTION_SEND || from.type != "text/plain") return null
        return from.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
            ?.take(LinkInspector.MAX_TEXT_CHARS + 1)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        incomingSharedText = extractSharedText(intent)
        setContent { MaterialTheme { KanafScreen(this, incomingSharedText) } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        incomingSharedText = extractSharedText(intent)
    }
}

@Composable
private fun KanafScreen(activity: Activity, sharedText: String?) {
    val scope = rememberCoroutineScope()
    var status by remember { mutableStateOf("اختر ملفًا لفحص بصمته محليًا") }
    var busy by remember { mutableStateOf(false) }
    var selfTestStatus by remember { mutableStateOf("") }
    var hasScanReport by remember { mutableStateOf(false) }
    var watchNewApps by remember { mutableStateOf(ProtectionControl.installWatchEnabled(activity)) }
    var periodicChecks by remember { mutableStateOf(ProtectionControl.periodicEnabled(activity)) }
    var protectionStatus by remember { mutableStateOf(ProtectionControl.lastResult(activity)) }
    val notificationPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (!granted) protectionStatus = "Notifications disabled by Android. Checks still require opt-in."
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
                protectionStatus = "Selected-folder SHA-256 check scheduled approximately every 24 hours."
            }.onFailure {
                protectionStatus = "Folder access unavailable: " + it.javaClass.simpleName
            }
        }
    }
    var vaultStatus by remember { mutableStateOf("") }
    var pendingRestoreId by rememberSaveable { mutableStateOf<String?>(null) }
    val inventory = remember { InstalledAppInventory() }
    var appEntries by remember { mutableStateOf<List<InstalledAppInventory.Entry>>(emptyList()) }
    var appsLoaded by remember { mutableStateOf(false) }
    var appsStatus by remember { mutableStateOf("") }
    val vault = remember { EncryptedVault() }
    val vaultEntries = remember { mutableStateListOf<EncryptedVault.Entry>().also {
        it.addAll(runCatching { vault.list(activity) }.getOrDefault(emptyList()))
    } }
    fun reloadVault() {
        vaultEntries.clear()
        vaultEntries.addAll(vault.list(activity))
    }
    val arabic = java.util.Locale.getDefault().language == "ar"
    fun localized(ar: String, en: String) = if (arabic) ar else en
    val quarantinePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null && !busy) {
            busy = true
            scope.launch {
                val result = withContext(Dispatchers.IO) {
                    runCatching { SafQuarantine(vault).isolateSelectedDocument(activity, uri) }
                }
                val outcome = result.getOrNull()
                vaultStatus = when (outcome) {
                    is SafQuarantine.Outcome.Moved -> localized(
                        "تمت إزالة المستند المختار عبر مزوّد أندرويد بعد التحقق من نسخته المشفرة. احتفظ بمفتاح الجهاز لاستعادته.",
                        "The selected SAF document was deleted by Android's provider after its encrypted copy was verified. Retain your device key for restore.")
                    is SafQuarantine.Outcome.CopyOnly -> localized(
                        "لم يُعزل الملف الأصلي؛ بقيت نسخة مشفرة فقط في الخزنة: ",
                        "Original was NOT isolated; encrypted copy only: ") + outcome.reason
                    is SafQuarantine.Outcome.Failed -> localized(
                        "لم ينجح الحفظ أو العزل: ", "Could not save or isolate: ") + outcome.reason
                    null -> localized("فشلت العملية قبل اكتمالها.", "Quarantine operation failed.")
                }
                reloadVault()
                busy = false
            }
        }
    }
    val vaultPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null && !busy) {
            busy = true
            scope.launch {
                val result = withContext(Dispatchers.IO) {
                    runCatching { vault.store(activity, uri) }
                }
                vaultStatus = if (result.isSuccess) {
                    reloadVault()
                    localized("حُفظت نسخة مشفرة داخل كنف. لم يُحذف الملف الأصلي.",
                        "Encrypted copy saved in Kanaf. The source file was not deleted.")
                } else {
                    localized("تعذر حفظ النسخة المشفرة: ", "Encrypted copy failed: ") +
                        result.exceptionOrNull()?.javaClass?.simpleName
                }
                busy = false
            }
        }
    }
    val restorePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        val id = pendingRestoreId
        pendingRestoreId = null
        if (uri != null && id != null && !busy) {
            busy = true
            scope.launch {
                val result = withContext(Dispatchers.IO) {
                    runCatching { vault.restore(activity, id, uri) }
                }
                vaultStatus = if (result.isSuccess) {
                    localized("اكتملت الاستعادة إلى المستند الذي اخترته. النسخة المشفرة ما زالت محفوظة.",
                        "Restored to your chosen document. The encrypted copy remains in the vault.")
                } else {
                    localized(
                        "فشلت الاستعادة. قد يكون المستند الجديد غير مكتمل؛ احذفه قبل المحاولة مجددًا: ",
                        "Restore failed. The destination may contain partial data; delete it before retrying: "
                    ) + result.exceptionOrNull()?.javaClass?.simpleName
                }
                busy = false
            }
        }
    }
    val scanHistory = remember { mutableStateListOf<String>() }
    var keepSessionHistory by rememberSaveable { mutableStateOf(true) }
    var signatures by remember {
        mutableStateOf(runCatching { SignatureRepository(activity).load() }.getOrNull())
    }
    val trustedFeed = remember { ProductionFeedInstaller() }
    var feedStatus by remember { mutableStateOf("") }
    val feedPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null && !busy) {
            busy = true
            scope.launch {
                val outcome = withContext(Dispatchers.IO) {
                    runCatching { trustedFeed.importSignedZip(activity, uri) }
                }
                if (outcome.isSuccess) {
                    signatures = runCatching { SignatureRepository(activity).load() }.getOrNull()
                    feedStatus = localized("قاعدة التوقيعات الموقعة مثبتة؛ الإصدار ",
                        "Verified signature database installed, version ") + outcome.getOrThrow()
                } else {
                    feedStatus = localized("رُفض التحديث غير الموثوق أو غير الصالح: ",
                        "Untrusted or invalid feed rejected: ") +
                        outcome.exceptionOrNull()?.javaClass?.simpleName
                }
                busy = false
            }
        }
    }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            busy = true
            hasScanReport = false
            status = "جارٍ الفحص..."
            scope.launch {
                val completed = withContext(Dispatchers.IO) {
                    try {
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
                                        "APK: DEX=${result.summary.dexFiles}، مكتبات أصلية=${result.summary.nativeLibraries}، مسارات مريبة=${result.summary.unsafePaths}. فحص بنية فقط وليس كشف برمجيات خبيثة."
                                    is ApkStructureInspector.Result.Incomplete ->
                                        "فحص بنية APK غير مكتمل: ${result.reason}"
                                }
                            } ?: "تعذر فتح APK"
                        } else ""
                        var dexEvidence: DexHeaderInspector.Result? = null
                        val dexNote = if (apk) {
                            activity.contentResolver.openInputStream(uri)?.use { stream ->
                                when (val result = DexHeaderInspector().inspect(stream).also { dexEvidence = it }) {
                                    is DexHeaderInspector.Result.Complete ->
                                        "DEX: ${result.summary.dexFiles} ملف، رؤوس غير سليمة: ${result.summary.invalidHeaders}. فحص سلامة بنية فقط."
                                    is DexHeaderInspector.Result.Incomplete ->
                                        "فحص DEX غير مكتمل: ${result.reason}"
                                }
                            } ?: "تعذر فتح APK لفحص DEX"
                        } else ""
                        var zipEvidence: ZipInspector.Result? = null
                        val zipNote = if (archive || apk) {
                            activity.contentResolver.openInputStream(uri)?.use { stream ->
                                when (val inspected = ZipInspector().inspect(stream).also { zipEvidence = it }) {
                                    is ZipInspector.Result.Complete ->
                                        "ZIP: ${inspected.summary.entries} مدخل، ${inspected.summary.bytesExpanded} بايت بعد الفك، مسارات خطرة: ${inspected.summary.unsafeNames}. لا يشمل تحليل المحتوى الخبيث."
                                    is ZipInspector.Result.Incomplete ->
                                        "تحليل الأرشيف غير مكتمل: ${inspected.reason}"
                                }
                            } ?: "تعذر فتح الأرشيف"
                        } else ""
                        run {
                            val scanResult = HashSignatureEngine(signatures).scan({
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
                            val nativeNote = listOf(
                                "فحص أصلي محلي (قاعدة اختبار EICAR فقط؛ ليست حماية شاملة):",
                                ScanEvidenceText.nativeLabel("ClamAV", native.clamav, snapshotConflict),
                                ScanEvidenceText.nativeLabel("YARA-X", native.yaraX, snapshotConflict)
                            ).joinToString("\n")
                            val eicarOnly = consensus is EngineConsensus.Decision.Threat &&
                                consensus.detections.all {
                                    (it.verdict as AntivirusEngine.Verdict.Detected)
                                        .threatName.contains("eicar", ignoreCase = true)
                                }
                            val consensusNote = when (consensus) {
                                is EngineConsensus.Decision.Threat ->
                                    if (eicarOnly) "نتيجة المحركات: نجاح اكتشاف EICAR التجريبي غير الضار"
                                    else "نتيجة المحركات: تم اكتشاف تهديد معروف"
                                is EngineConsensus.Decision.Inconclusive ->
                                    if (consensus.reason == "file-changed-between-engines") {
                                        "تحذير: اختلفت بصمات الملف بين المحركات. قد يكون الملف تغيّر أثناء الفحص؛ النتائج غير حاسمة ويجب إعادة الفحص."
                                    } else "نتيجة المحركات: غير مكتملة"
                                is EngineConsensus.Decision.NoKnownMatch -> "نتيجة المحركات: لا يوجد تطابق معروف؛ السلامة غير مؤكدة"
                            }
                            val verdict = ScanEvidenceText.hashLabel(
                                scanResult, signatures?.size ?: 0, snapshotConflict
                            )
                            val features = ThreatFeatureVector.from(apkEvidence, dexEvidence, zipEvidence)
                            val modelResult = UnavailableThreatModel.classify(features)
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
                                "عينة EICAR اختبارية آمنة؛ نجاح الكشف لا يثبت القدرة على كشف فيروسات فعلية"
                            } else if (scanResult is AntivirusEngine.Verdict.Incomplete || signatures == null || structuralIncomplete || consensus is EngineConsensus.Decision.Inconclusive) {
                                "تقييم الأدلة: الفحص غير مكتمل أو قاعدة التوقيعات غير متاحة"
                            } else when (assessment.severity) {
                                ThreatEvidence.Severity.CONFIRMED -> "تقييم الأدلة: تطابق تهديد معروف"
                                ThreatEvidence.Severity.SUSPICIOUS -> "تقييم الأدلة: مؤشرات مشبوهة تستدعي المراجعة"
                                ThreatEvidence.Severity.INCONCLUSIVE -> "تقييم الأدلة: تحليل غير مكتمل"
                                ThreatEvidence.Severity.NO_KNOWN_MATCH -> "تقييم الأدلة: لا توجد مؤشرات معروفة؛ السلامة غير مؤكدة"
                            }
                            val journey = TrustJourney.build(
                                assessment,
                                scanCompleted = scanResult !is AntivirusEngine.Verdict.Incomplete && !structuralIncomplete && consensus !is EngineConsensus.Decision.Inconclusive,
                                signaturesAvailable = signatures != null
                            )
                            val decisionNote = if (eicarOnly) {
                                "اختبار EICAR ناجح. اختبر ملفًا آخر أو راجع حدود قواعد الكشف التجريبية."
                            } else if (snapshotConflict) {
                                "خطوتك التالية: أعد فحص الملف بعد التأكد من ثباته؛ لا تعتمد أي حكم كشف أو سلامة من النتائج المتعارضة."
                            } else "خطوتك التالية: ${journey.title} — ${journey.nextStep}"
                            val aiNote = when (modelResult) {
                                is ThreatModel.Prediction.Unavailable -> "التحليل بالذكاء الاصطناعي غير متاح بعد؛ لم يتم تشغيل نموذج مدرّب."
                                is ThreatModel.Prediction.Scored -> "نتيجة النموذج: ${modelResult.riskProbability}"
                            }
                            listOf(decisionNote, assessmentNote, consensusNote, nativeNote, aiNote, verdict, apkNote, dexNote, zipNote)
                                .filter { it.isNotEmpty() }.joinToString("\n")
                        }
                    } catch (e: Exception) {
                        "تعذر إكمال الفحص: ${e.javaClass.simpleName}"
                    }
                }
                status = completed
                hasScanReport = true
                // Only a bounded, non-persistent summary; never retain file names or contents.
                com.kanaf.alrasby.engine.SessionHistoryPolicy.record(scanHistory, completed, keepSessionHistory)
                busy = false
            }
        }
    }
    KanafGlassHome(
        busy = busy,
        sharedText = sharedText,
        scanHistory = scanHistory,
        watchNewApps = watchNewApps,
        periodicChecks = periodicChecks,
        protectionStatus = protectionStatus,
        onWatchNewApps = { enabled ->
            ProtectionControl.setInstallWatch(activity, enabled)
            watchNewApps = enabled
            protectionStatus = if (enabled)
                localized("مراقبة تثبيت التطبيقات مفعلة؛ تنبيه للمراجعة فقط.",
                    "Install-event review enabled; alert-only, not antivirus scanning.")
            else localized("تم إيقاف مراقبة التثبيت.", "Install-event review disabled.")
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
                protectionStatus = localized("أُلغي الفحص الدوري وسُحب اختيار المجلد.",
                    "Scheduled checks cancelled; selected folder removed.")
            }
        },
        onRunScopedCheck = {
            if (periodicChecks && !busy) {
                WorkManager.getInstance(activity).enqueue(
                    OneTimeWorkRequestBuilder<ScopedFileCheckWorker>().build()
                )
                protectionStatus = localized("طُلب فحص للمجلد المحدد، وسيُنفذ عندما يسمح أندرويد.",
                    "Folder check requested. Android will run it when scheduled.")
            }
        },
        onRefreshProtection = { protectionStatus = ProtectionControl.lastResult(activity) },
        hasScanReport = hasScanReport,
        canImportSignedFeed = trustedFeed.configured(),
        signedFeedStatus = feedStatus,
        onImportSignedFeed = { if (!busy && trustedFeed.configured())
            feedPicker.launch(arrayOf("application/zip", "application/octet-stream")) },
        onShareReport = {
            if (hasScanReport && !busy) runCatching {
                val share = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, status.take(15_000))
                }
                activity.startActivity(Intent.createChooser(
                    share, localized("مشاركة تقرير الفحص", "Share scan report")
                ))
            }.onFailure {
                vaultStatus = localized("تعذر فتح واجهة المشاركة", "Sharing is unavailable")
            }
        },
        vaultItems = vaultEntries,
        vaultStatus = vaultStatus,
        installedApps = appEntries,
        appsLoaded = appsLoaded,
        appsStatus = appsStatus,
        onLoadApps = {
            if (!busy) {
                busy = true
                scope.launch {
                    val found = withContext(Dispatchers.IO) {
                        runCatching { inventory.load(activity) }
                    }
                    if (found.isSuccess) {
                        appEntries = found.getOrThrow()
                        appsLoaded = true
                        appsStatus = localized(
                            "هذه التطبيقات القابلة للتشغيل الظاهرة لكنف فقط؛ لم يتم فحصها بحثًا عن البرمجيات الخبيثة.",
                            "Only launchable apps visible to Kanaf are listed; no malware scanning was performed."
                        )
                    } else {
                        appsStatus = localized("تعذر قراءة قائمة التطبيقات", "Could not list visible applications")
                    }
                    busy = false
                }
            }
        },
        onOpenAppDetails = { packageName ->
            runCatching {
                activity.startActivity(inventory.settingsIntent(packageName))
            }.onFailure {
                appsStatus = localized("تعذر فتح صفحة التطبيق", "Could not open Android app details")
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
                busy = true
                scope.launch {
                    val removed = withContext(Dispatchers.IO) {
                        runCatching { vault.delete(activity, id) }.getOrDefault(false)
                    }
                    reloadVault()
                    vaultStatus = if (removed) localized(
                        "حُذفت النسخة المشفرة من خزنة كنف فقط.",
                        "The encrypted copy was deleted from Kanaf's vault only."
                    ) else localized("لم تُحذف النسخة؛ تحقق من التخزين",
                        "Vault copy could not be removed")
                    busy = false
                }
            }
        },
        keepSessionHistory = keepSessionHistory,
        onSessionHistoryChanged = { enabled ->
            keepSessionHistory = enabled
            com.kanaf.alrasby.engine.SessionHistoryPolicy.onEnabledChanged(scanHistory, enabled)
        },
        onClearHistory = { scanHistory.clear() },
        selfTestStatus = selfTestStatus,
        onTestEngines = {
            if (!busy) {
                busy = true
                scope.launch {
                    selfTestStatus = withContext(Dispatchers.IO) {
                        val testResult = NativeScannerBridge.selfTest(activity)
                        fun label(name: String, verdict: AntivirusEngine.Verdict): String =
                            when (verdict) {
                                is AntivirusEngine.Verdict.Detected -> "$name: نجح اكتشاف عينة EICAR الآمنة"
                                is AntivirusEngine.Verdict.NoKnownMatch -> "$name: فشل اكتشاف عينة EICAR"
                                is AntivirusEngine.Verdict.Incomplete -> "$name: اختبار غير مكتمل (" + verdict.reason + ")"
                            }
                        listOf(
                            "اختبار كشف حقيقي عبر المحركات الأصلية — عينة EICAR غير ضارة:",
                            label("ClamAV", testResult.clamav),
                            label("YARA-X", testResult.yaraX)
                        ).joinToString("\n")
                    }
                    busy = false
                }
            }
        },
        status = status,
        onPickFile = { picker.launch(arrayOf("*/*")) },
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
                android.widget.Toast.makeText(activity, "تعذر فتح المتصفح", android.widget.Toast.LENGTH_SHORT).show()
            }
        }
    )
}
