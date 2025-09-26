package com.bioauth.sample

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.biometric.BiometricManager
import androidx.fragment.app.FragmentActivity
import com.bioauth.lib.manager.BioAuthSettings
import com.bioauth.lib.manager.IBioAuthManager

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    BioAuthApp()
                }
            }
        }
    }
}

@Composable
fun BioAuthApp() {
    var isLoggedIn by remember { mutableStateOf(false) }

    if (isLoggedIn) {
        LoggedInScreen(
            onLogout = { isLoggedIn = false }
        )
    } else {
        LoginScreen(
            onLoginSuccess = { isLoggedIn = true }
        )
    }
}

// Extension functions
fun getAuthenticator() = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.BIOMETRIC_WEAK
fun IBioAuthManager.getBiometricsState() = this.getBiometricsState(getAuthenticator())
fun IBioAuthManager.isFingerprintEnrolled() = this.getBiometricsState() == IBioAuthManager.AuthenticationTypes.SUCCESS

// Convert to suspend function for proper coroutine handling
suspend fun IBioAuthManager.isFingerprintReadyToUse(): Boolean {
    return this.isFingerprintEnrolled() &&
           this.isFingerEnabled().fold(
               onSuccess = { it == BioAuthSettings.BiometricStatus.Enabled },
               onFailure = { false }
           )
}