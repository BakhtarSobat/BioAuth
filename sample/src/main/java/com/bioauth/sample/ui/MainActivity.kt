package com.bioauth.sample.ui

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.biometric.BiometricManager
import androidx.fragment.app.FragmentActivity
import com.bioauth.lib.manager.authentication.AuthenticationSettings
import com.bioauth.lib.manager.authentication.biometrics.BiometricAuthenticationManager
import com.bioauth.sample.ui.enrolment.LoggedInScreen
import com.bioauth.sample.ui.login.LoginScreen

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
            onEnrol = { isLoggedIn = true }
        )
    }
}

// Extension functions
fun getAuthenticator() = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.BIOMETRIC_WEAK
fun BiometricAuthenticationManager.getBiometricsState() = this.getBiometricsState(getAuthenticator())
fun BiometricAuthenticationManager.isFingerprintEnrolled() = this.getBiometricsState() == BiometricAuthenticationManager.AuthenticationTypes.SUCCESS

// Convert to suspend function for proper coroutine handling
suspend fun BiometricAuthenticationManager.isFingerprintReadyToUse(): Boolean {
    return this.isFingerprintEnrolled() &&
           this.getBiometricEnrolmentStatus() == AuthenticationSettings.EnrolmentStatus.Enabled
}