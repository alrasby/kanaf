package com.kanaf.alrasby

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
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
import com.kanaf.alrasby.engine.NativeScannerBridge
import com.kanaf.alrasby.engine.SignatureRepository
import com.kanaf.alrasby.engine.DexHeaderInspector
import com.kanaf.alrasby.engine.ApkStructureInspector
import com.kanaf.alrasby.engine.ZipInspector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { KanafScreen(this) } }
    }
}

@Composable
private fun KanafScreen(activity: Activity) {
    val scope = rememberCoroutineScope()
    var status by remember { mutableStateOf("اختر ملفًا لفحص بصمته محليًا") }
    var busy by remember { mutableStateOf(false) }
    val signatures = remember {
        runCatching { SignatureRepository(activity).load() }.getOrNull()
    }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            busy = true
            status = "جارٍ الفحص..."
            scope.launch {
                status = withContext(Dispatchers.IO) {
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
                            fun nativeLabel(name: String, result: AntivirusEngine.Verdict): String =
                                when (result) {
                                    is AntivirusEngine.Verdict.Detected ->
                                        "$" + "{name}: كشف تجريبي EICAR — $" + "{result.threatName}"
                                    is AntivirusEngine.Verdict.NoKnownMatch ->
                                        "$" + "{name}: لا تطابق مع قاعدة EICAR الاختبارية"
                                    is AntivirusEngine.Verdict.Incomplete ->
                                        "$" + "{name}: لم يكتمل الفحص ($" + "{result.reason})"
                                }
                            val nativeNote = listOf(
                                "فحص أصلي محلي (قاعدة اختبار EICAR فقط؛ ليست حماية شاملة):",
                                nativeLabel("ClamAV", native.clamav),
                                nativeLabel("YARA-X", native.yaraX)
                            ).joinToString("\n")
                            val consensusNote = when (consensus) {
                                is EngineConsensus.Decision.Threat -> "نتيجة المحركات: تم اكتشاف تهديد معروف"
                                is EngineConsensus.Decision.Inconclusive -> "نتيجة المحركات: غير مكتملة"
                                is EngineConsensus.Decision.NoKnownMatch -> "نتيجة المحركات: لا يوجد تطابق معروف؛ السلامة غير مؤكدة"
                            }
                            val verdict = when (scanResult) {
                                is AntivirusEngine.Verdict.Detected ->
                                    "تطابق توقيع تهديد: ${scanResult.threatName}\nSHA-256: ${scanResult.sha256}"
                                is AntivirusEngine.Verdict.NoKnownMatch ->
                                    "لم يُعثر على تطابق في ${signatures?.size ?: 0} توقيع محلي. هذا لا يعني أن الملف آمن.\nSHA-256: ${scanResult.sha256}"
                                is AntivirusEngine.Verdict.Incomplete ->
                                    "الفحص غير مكتمل: ${scanResult.reason}"
                            }
                            val features = ThreatFeatureVector.from(apkEvidence, dexEvidence, zipEvidence)
                            val modelResult = UnavailableThreatModel.classify(features)
                            val nativeDetection = nativeReports.firstNotNullOfOrNull {
                                (it.verdict as? AntivirusEngine.Verdict.Detected)?.threatName
                            }
                            val assessment = ThreatEvidence.assess(
                                (scanResult as? AntivirusEngine.Verdict.Detected)?.threatName ?: nativeDetection,
                                apkEvidence, dexEvidence, zipEvidence
                            )
                            val structuralMissing = (apk && (apkEvidence == null || dexEvidence == null)) ||
                                ((archive || apk) && zipEvidence == null)
                            val assessmentNote = if (scanResult is AntivirusEngine.Verdict.Incomplete || signatures == null || structuralMissing || consensus is EngineConsensus.Decision.Inconclusive) {
                                "تقييم الأدلة: الفحص غير مكتمل أو قاعدة التوقيعات غير متاحة"
                            } else when (assessment.severity) {
                                ThreatEvidence.Severity.CONFIRMED -> "تقييم الأدلة: تطابق تهديد معروف"
                                ThreatEvidence.Severity.SUSPICIOUS -> "تقييم الأدلة: مؤشرات مشبوهة تستدعي المراجعة"
                                ThreatEvidence.Severity.INCONCLUSIVE -> "تقييم الأدلة: تحليل غير مكتمل"
                                ThreatEvidence.Severity.NO_KNOWN_MATCH -> "تقييم الأدلة: لا توجد مؤشرات معروفة؛ السلامة غير مؤكدة"
                            }
                            val journey = TrustJourney.build(
                                assessment,
                                scanCompleted = scanResult !is AntivirusEngine.Verdict.Incomplete && !structuralMissing && consensus !is EngineConsensus.Decision.Inconclusive,
                                signaturesAvailable = signatures != null
                            )
                            val decisionNote = "خطوتك التالية: ${journey.title} — ${journey.nextStep}"
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
                busy = false
            }
        }
    }
    KanafGlassHome(
        busy = busy,
        status = status,
        onPickFile = { picker.launch(arrayOf("*/*")) },
        onOpenWebsite = {
            runCatching {
                activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://nabdhserv.net")))
            }.onFailure {
                android.widget.Toast.makeText(activity, "تعذر فتح المتصفح", android.widget.Toast.LENGTH_SHORT).show()
            }
        }
    )
}
