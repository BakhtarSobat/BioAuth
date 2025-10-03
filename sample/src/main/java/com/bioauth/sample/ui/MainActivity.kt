package com.bioauth.sample.ui

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
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
