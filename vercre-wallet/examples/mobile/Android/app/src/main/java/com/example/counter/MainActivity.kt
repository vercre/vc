@file:OptIn(ExperimentalUnsignedTypes::class)

package com.example.counter

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.counter.shared_types.Event
import com.example.counter.ui.theme.CounterTheme
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.http.*
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            CounterTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background
                ) { View() }
            }
        }
    }
}

@Composable
fun View(core: Core = viewModel()) {
    val coroutineScope = rememberCoroutineScope()
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
        modifier = Modifier
            .fillMaxSize()
            .padding(10.dp),
    ) {
        Text(text = "Credibil Wallet", fontSize = 30.sp, modifier = Modifier.padding(10.dp))
        Text(text = "Rust Core, Kotlin Shell (Jetpack Compose)", modifier = Modifier.padding(10.dp))
        Text(
            text = core.view.text, color = if (core.view.confirmed) {
                Color.Black
            } else {
                Color.Gray
            }, modifier = Modifier.padding(10.dp)
        )
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(
                onClick = {
                    coroutineScope.launch { core.update(Event.Decrement()) }
                }, colors = ButtonDefaults.buttonColors(
                    containerColor = Color.hsl(44F, 1F, 0.77F)
                )
            ) { Text(text = "Decrement", color = Color.DarkGray) }
            Button(
                onClick = {
                    coroutineScope.launch { core.update(Event.Increment()) }
                }, colors = ButtonDefaults.buttonColors(
                    containerColor = Color.hsl(348F, 0.86F, 0.61F)
                )
            ) { Text(text = "Increment", color = Color.White) }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun DefaultPreview() {
    CounterTheme { View() }
}
