package com.kanaf.alrasby

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp

/** Decorative emblem only: it never represents a device-wide security verdict. */
@Composable
internal fun KanafShieldEmblem(busy: Boolean, dark: Boolean) {
    val emerald = Color(0xFF3DDFB0)
    val ice = Color(0xFFB2F5E7)
    val muted = if (dark) Color(0xFF72A5A8) else Color(0xFF66999B)
    Box(contentAlignment = Alignment.Center) {
        Canvas(Modifier.size(156.dp)) {
            val center = Offset(size.width / 2f, size.height / 2f)
            drawCircle(
                brush = Brush.radialGradient(
                    listOf(emerald.copy(alpha = if (dark) 0.22f else 0.14f), Color.Transparent),
                    center = center,
                    radius = size.minDimension * 0.5f
                ),
                radius = size.minDimension * 0.5f,
                center = center
            )
            drawCircle(muted.copy(alpha = 0.38f), radius = size.minDimension * 0.41f,
                center = center, style = Stroke(width = 1.5.dp.toPx()))
            drawCircle(emerald.copy(alpha = 0.22f), radius = size.minDimension * 0.33f,
                center = center, style = Stroke(width = 1.dp.toPx()))
            val x = size.width
            val y = size.height
            val shield = Path().apply {
                moveTo(x * 0.5f, y * 0.24f)
                cubicTo(x * 0.59f, y * 0.31f, x * 0.67f, y * 0.32f, x * 0.72f, y * 0.33f)
                lineTo(x * 0.72f, y * 0.53f)
                cubicTo(x * 0.72f, y * 0.66f, x * 0.61f, y * 0.75f, x * 0.5f, y * 0.81f)
                cubicTo(x * 0.39f, y * 0.75f, x * 0.28f, y * 0.66f, x * 0.28f, y * 0.53f)
                lineTo(x * 0.28f, y * 0.33f)
                cubicTo(x * 0.34f, y * 0.32f, x * 0.41f, y * 0.31f, x * 0.5f, y * 0.24f)
                close()
            }
            drawPath(shield, brush = Brush.verticalGradient(listOf(ice, emerald)),
                style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round))
            drawLine(ice, Offset(x * 0.39f, y * 0.53f),
                Offset(x * 0.47f, y * 0.61f), strokeWidth = 3.dp.toPx(), cap = StrokeCap.Round)
            drawLine(ice, Offset(x * 0.47f, y * 0.61f),
                Offset(x * 0.63f, y * 0.44f), strokeWidth = 3.dp.toPx(), cap = StrokeCap.Round)
        }
        if (busy) {
            CircularProgressIndicator(
                modifier = Modifier.size(146.dp),
                color = emerald,
                trackColor = Color.Transparent,
                strokeWidth = 3.dp
            )
        }
    }
}
