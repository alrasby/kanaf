package com.kanaf.alrasby

import android.app.Activity
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
import com.kanaf.alrasby.engine.ThreatEvidence
import com.kanaf.alrasby.engine.StreamScanner
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
                        activity.contentResolver.openInputStream(uri)?.use { input ->
                            val verdict = when (val result = StreamScanner(signatures = signatures ?: emptyMap()).scan(input)) {
                                is StreamScanner.Result.Completed ->
                                    when {
                                        signatures == null -> "تعذر تحميل قاعدة التوقيعات؛ النتيجة غير معروفة. SHA-256: ${result.sha256}"
                                        result.signature != null -> "تطابق توقيع تهديد: ${result.signature}\nSHA-256: ${result.sha256}"
                                        else -> "لم يُعثر على تطابق في ${signatures.size} توقيع محلي. هذا لا يعني أن الملف آمن.\nSHA-256: ${result.sha256}"
                                    }
                                is StreamScanner.Result.Skipped -> "الفحص غير مكتمل: ${result.reason}"
                            }
                            val assessment = ThreatEvidence.assess(
                                (result as? StreamScanner.Result.Completed)?.signature,
                                apkEvidence, dexEvidence, zipEvidence
                            )
                            val assessmentNote = when (assessment.severity) {
                                ThreatEvidence.Severity.CONFIRMED -> "تقييم الأدلة: تطابق تهديد معروف"
                                ThreatEvidence.Severity.SUSPICIOUS -> "تقييم الأدلة: مؤشرات مشبوهة تستدعي المراجعة"
                                ThreatEvidence.Severity.INCONCLUSIVE -> "تقييم الأدلة: تحليل غير مكتمل"
                                ThreatEvidence.Severity.NO_KNOWN_MATCH -> "تقييم الأدلة: لا توجد مؤشرات معروفة؛ السلامة غير مؤكدة"
                            }
                            listOf(assessmentNote, verdict, apkNote, dexNote, zipNote)
                                .filter { it.isNotEmpty() }.joinToString("\n")
                        } ?: "تعذر فتح الملف"
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
        onPickFile = { picker.launch(arrayOf("*/*")) }
    )
}
