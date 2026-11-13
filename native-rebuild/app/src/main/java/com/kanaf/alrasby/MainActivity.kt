package com.kanaf.alrasby

import android.app.Activity
import android.content.Intent
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
import com.kanaf.alrasby.engine.StreamScanner
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
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            busy = true
            status = "جارٍ الفحص..."
            scope.launch {
                status = withContext(Dispatchers.IO) {
                    try {
                        activity.contentResolver.openInputStream(uri)?.use { input ->
                            when (val result = StreamScanner().scan(input)) {
                                is StreamScanner.Result.Completed ->
                                    "اكتمل حساب SHA-256: ${result.sha256}\nلا توجد قاعدة تهديدات محمّلة؛ لا يمكن الحكم على سلامة الملف."
                                is StreamScanner.Result.Skipped -> "الفحص غير مكتمل: ${result.reason}"
                            }
                        } ?: "تعذر فتح الملف"
                    } catch (e: Exception) {
                        "تعذر إكمال الفحص: ${e.javaClass.simpleName}"
                    }
                }
                busy = false
            }
        }
    }
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("كنف | Kanaf", style = MaterialTheme.typography.headlineMedium)
        Text("فحص محلي أولي — لا يحذف أو يرفع ملفاتك")
        Button(enabled = !busy, onClick = { picker.launch(arrayOf("*/*")) }) {
            Text(if (busy) "جارٍ الفحص" else "اختيار ملف للفحص")
        }
        Text(status)
    }
}
