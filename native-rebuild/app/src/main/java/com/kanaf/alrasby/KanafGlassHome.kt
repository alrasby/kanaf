package com.kanaf.alrasby

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

private val Teal = Color(0xFF137C82)
private val Aqua = Color(0xFF66E2D1)
private val Night = Color(0xFF0B2530)

@Composable
fun KanafGlassHome(
    busy: Boolean,
    status: String,
    onPickFile: () -> Unit
) {
    val dark = isSystemInDarkTheme()
    val background = if (dark) Night else Color(0xFFF1F8F9)
    val ink = if (dark) Color(0xFFF0FBFA) else Night
    val secondary = if (dark) Color(0xFFB4CDCF) else Color(0xFF47666C)
    val card = if (dark) Color(0xFF24444E).copy(alpha = 0.85f) else Color.White.copy(alpha = 0.84f)
    val stroke = if (dark) Aqua.copy(alpha = 0.24f) else Color.White.copy(alpha = 0.95f)

    MaterialTheme(colorScheme = if (dark) darkColorScheme(primary = Aqua, surface = Night, onSurface = ink)
        else lightColorScheme(primary = Teal, surface = background, onSurface = ink)) {
        Box(
            Modifier.fillMaxSize().background(
                Brush.verticalGradient(
                    if (dark) listOf(Night, Color(0xFF12414B), Night)
                    else listOf(Color(0xFFDDF5F2), background, Color(0xFFE5F0F6))
                )
            )
        ) {
            Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp, vertical = 28.dp),
                verticalArrangement = Arrangement.spacedBy(18.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("◈", color = if (dark) Aqua else Teal, style = MaterialTheme.typography.headlineLarge)
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text("كنف", color = ink, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                        Text("KANAF · LOCAL SECURITY", color = secondary, style = MaterialTheme.typography.labelSmall)
                    }
                }
                GlassPanel(card, stroke) {
                    Text("مركز الحماية", color = secondary, style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(12.dp))
                    Text(
                        if (busy) "الفحص جارٍ…" else "جاهز لفحص ملف",
                        color = ink, style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "خصوصيتك أولًا. يتم تحليل الملف محليًا دون رفعه أو حذفه.",
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
                        Text(if (busy) "جارٍ الفحص…" else "اختيار ملف للفحص", fontWeight = FontWeight.Bold)
                    }
                    if (busy) {
                        Spacer(Modifier.height(12.dp))
                        LinearProgressIndicator(Modifier.fillMaxWidth(), color = Aqua)
                    }
                }
                GlassPanel(card, stroke) {
                    Text("نتيجة الفحص", color = ink, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(12.dp))
                    Text(status, color = secondary, style = MaterialTheme.typography.bodyMedium)
                }
                GlassPanel(card, stroke) {
                    Text("قدرات الفحص الحالية", color = ink, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(10.dp))
                    Text("SHA-256  •  ZIP  •  APK  •  DEX", color = if (dark) Aqua else Teal,
                        style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "فحص بنية الملفات ومطابقة التوقيعات المحلية المتاحة. عدم العثور على تطابق لا يثبت سلامة الملف.",
                        color = secondary, style = MaterialTheme.typography.bodySmall
                    )
                }
                Text(
                    "نسخة تطويرية · لا توفر حماية شاملة أو فحصًا تلقائيًا للجهاز",
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
