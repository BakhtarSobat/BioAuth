package com.bioauth.sample

import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.bioauth.lib.manager.BioAuthManager
import com.bioauth.lib.manager.BioAuthSettings
import com.bioauth.lib.manager.IBioAuthManager.AuthenticationTypes.HARDWARE_UNAVAILABLE
import com.bioauth.lib.manager.IBioAuthManager.AuthenticationTypes.NONE_ENROLLED
import com.bioauth.lib.manager.IBioAuthManager.AuthenticationTypes.NO_HARDWARE
import com.bioauth.lib.manager.IBioAuthManager.AuthenticationTypes.SUCCESS
import com.bioauth.lib.manager.IBioAuthManager.AuthenticationTypes.UNKNOWN
import com.bioauth.sample.server.MyServer
import kotlinx.coroutines.launch

@Composable
fun LoggedInScreen(onLogout: () -> Unit) {
    val context = LocalContext.current
    val bioAuthManager = remember { createBioAuthManager(context) }
    val myServer = remember { MyServer(context) }
    val scope = rememberCoroutineScope()

    var fingerprintEnabled by remember { mutableStateOf(false) }
    var isLoading by remember { mutableStateOf(true) }

    // Check fingerprint status on composition
    LaunchedEffect(bioAuthManager) {
        bioAuthManager.isFingerEnabled().fold(
            onSuccess = { status ->
                fingerprintEnabled = status == BioAuthSettings.BiometricStatus.Enabled
                isLoading = false
            },
            onFailure = {
                fingerprintEnabled = false
                isLoading = false
            }
        )
    }

    val biometricsState = bioAuthManager.getBiometricsState(BiometricManager.Authenticators.BIOMETRIC_STRONG)
    val canUseBiometrics = biometricsState == SUCCESS

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = when (biometricsState) {
                SUCCESS -> "Welcome"
                NO_HARDWARE -> "No Hardware"
                HARDWARE_UNAVAILABLE -> "SDK not supported"
                NONE_ENROLLED -> "Please enroll at least one fingerprint"
                UNKNOWN -> "SDK not supported"
            },
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(32.dp))

        if (isLoading) {
            CircularProgressIndicator()
        } else if (canUseBiometrics || biometricsState == NONE_ENROLLED) {
            Button(
                onClick = {
                    scope.launch {
                        handleEnrollFingerprint(
                            bioAuthManager = bioAuthManager,
                            myServer = myServer,
                            context = context,
                            isEnabled = fingerprintEnabled,
                            onStateChanged = { fingerprintEnabled = it }
                        )
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (fingerprintEnabled) "Disable Fingerprint" else "Enroll Fingerprint")
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = onLogout,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Logout")
        }
    }
}

private suspend fun handleEnrollFingerprint(
    bioAuthManager: BioAuthManager,
    myServer: MyServer,
    context: android.content.Context,
    isEnabled: Boolean,
    onStateChanged: (Boolean) -> Unit
) {
    if (isEnabled) {
        bioAuthManager.resetAll()
        onStateChanged(false)
        return
    }

    bioAuthManager.enroll().fold(
        onSuccess = { publicKeyPem ->
            myServer.enrollFingerprint("1", publicKeyPem)
            bioAuthManager.enableFingerPrint(BioAuthSettings.BiometricStatus.Enabled)
            onStateChanged(true)
        },
        onFailure = { error ->
            Toast.makeText(context, "Couldn't enroll fingerprint: ${error.message}", Toast.LENGTH_LONG).show()
        }
    )
}

private fun createBioAuthManager(context: android.content.Context): BioAuthManager {
    return BioAuthManager.Builder(context, MyBioAuthSettings(context)).build()
}