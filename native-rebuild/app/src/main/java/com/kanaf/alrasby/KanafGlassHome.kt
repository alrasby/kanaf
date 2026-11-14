package com.kanaf.alrasby

import androidx.compose.foundation.clickable
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.isSystemInDarkTheme
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

private val Teal = Color(0xFF146C70)
private val Aqua = Color(0xFF3DDFB0)
private val Night = Color(0xFF0A1729)

@Composable
fun KanafGlassHome(
    busy: Boolean,
    status: String,
    onPickFile: () -> Unit,
    onOpenWebsite: () -> Unit
) {
    var page by remember { mutableIntStateOf(0) }
    val arabic = java.util.Locale.getDefault().language == "ar"
    fun tr(ar: String, en: String) = if (arabic) ar else en
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
                Modifier.fillMaxSize().verticalScroll(rememberScrollState())
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
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(7.dp)
                ) {
                    listOf(
                        tr("الفحص", "Scan"),
                        tr("المحركات", "Engines"),
                        tr("حول كنف", "About")
                    ).forEachIndexed { index, title ->
                        if (page == index) {
                            Button(
                                onClick = { page = index },
                                modifier = Modifier.weight(1f),
                                shape = RoundedCornerShape(14.dp),
                                contentPadding = PaddingValues(horizontal = 4.dp, vertical = 9.dp)
                            ) { Text(title, style = MaterialTheme.typography.labelMedium) }
                        } else {
                            OutlinedButton(
                                onClick = { page = index },
                                modifier = Modifier.weight(1f),
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
                        Text(tr("حدود الإصدار التجريبي", "Preview limitations"), color = ink,
                            style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Text(tr(
                            "الاختبارات على ملفات يختارها المستخدم فقط، وبحد 16 ميجابايت للمحركين. لا توجد قاعدة تهديدات شاملة أو حماية فورية أو فحص تلقائي للجهاز.",
                            "User-selected files only, maximum 16 MiB for native scanning. No comprehensive threat database, realtime protection, or automated device-wide scan."
                        ), color = secondary)
                    }
                }
                if (page == 2) {
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
