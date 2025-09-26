package com.bioauth.sample

import android.widget.Toast
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.bioauth.lib.manager.BioAuthManager
import com.bioauth.lib.manager.IBioAuthManager
import com.bioauth.sample.server.MyServer
import kotlinx.coroutines.launch
import java.util.*

private const val SALT = "SUPER_SALT"

@Composable
fun LoginScreen(onLoginSuccess: () -> Unit) {
    val context = LocalContext.current
    val activity = context as FragmentActivity
    val scope = rememberCoroutineScope()

    val myServer = remember { MyServer(context) }
    val bioAuthManager = remember { createBioAuthManager(context) }

    var pin by remember { mutableStateOf("") }
    var fingerprintState by remember { mutableStateOf(FingerprintState.IDLE) }

    val biometricsAvailable = bioAuthManager.getBiometricsState(
        androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
    ) == IBioAuthManager.AuthenticationTypes.SUCCESS

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        OutlinedTextField(
            value = pin,
            onValueChange = { pin = it },
            label = { Text("Enter PIN") },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = {
                if (myServer.loginWithPin(pin)) {
                    onLoginSuccess()
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Login")
        }

        if (biometricsAvailable) {
            Spacer(modifier = Modifier.height(32.dp))

            FingerprintSection(
                state = fingerprintState,
                onFingerprintClick = {
                    fingerprintState = FingerprintState.AUTHENTICATING
                    scope.launch {
                        showFingerprintDialog(
                            activity = activity,
                            bioAuthManager = bioAuthManager,
                            myServer = myServer,
                            onSuccess = {
                                fingerprintState = FingerprintState.SUCCESS
                                onLoginSuccess()
                            },
                            onError = {
                                fingerprintState = FingerprintState.ERROR
                            }
                        )
                    }
                }
            )
        }
    }
}

@Composable
fun FingerprintSection(
    state: FingerprintState,
    onFingerprintClick: () -> Unit
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Image(
            painter = painterResource(
                when (state) {
                    FingerprintState.IDLE -> R.drawable.ic_fingerprint
                    FingerprintState.AUTHENTICATING -> R.drawable.ic_fingerprint
                    FingerprintState.SUCCESS -> R.drawable.ic_check
                    FingerprintState.ERROR -> R.drawable.ic_error
                }
            ),
            contentDescription = "Fingerprint",
            modifier = Modifier
                .size(64.dp)
                .clickable(enabled = state == FingerprintState.IDLE) {
                    onFingerprintClick()
                }
        )

        Text(
            text = when (state) {
                FingerprintState.IDLE -> "Touch for fingerprint"
                FingerprintState.AUTHENTICATING -> "Authentication with the server..."
                FingerprintState.SUCCESS -> "Success!"
                FingerprintState.ERROR -> "Authentication failed"
            },
            style = MaterialTheme.typography.bodyMedium
        )
    }
}

enum class FingerprintState {
    IDLE, AUTHENTICATING, SUCCESS, ERROR
}

private suspend fun showFingerprintDialog(
    activity: FragmentActivity,
    bioAuthManager: IBioAuthManager,
    myServer: MyServer,
    onSuccess: () -> Unit,
    onError: () -> Unit
) {
    val executor = ContextCompat.getMainExecutor(activity)
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Biometric login for my app")
        .setSubtitle("Log in using your biometric credential")
        .setNegativeButtonText("Use account password")
        .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .build()

    val promptData = IBioAuthManager.PromptData(promptInfo, executor, null, activity)

    val challenge = myServer.getChallenge()
    val nonce = Random().nextInt(100)
    val stringToSign = "$challenge$SALT$nonce"
    val signable = MySignableObject(stringToSign)

    bioAuthManager.promptBiometricsAndSign(
        promptData,
        signable,
        object : IBioAuthManager.SigningCallback {
            override fun onSigningSuccess(signature: String) {
                val verified = myServer.verify(signature, nonce)
                if (verified) {
                    onSuccess()
                } else {
                    Toast.makeText(activity, "Unable to verify challenge", Toast.LENGTH_LONG).show()
                    onError()
                }
            }

            override fun onSigningError(errorCode: Int, message: String) {
                Toast.makeText(activity, "Signing error: $message", Toast.LENGTH_LONG).show()
                onError()
            }
        }
    ).fold(
        onSuccess = { /* Prompt started successfully */ },
        onFailure = {
            Toast.makeText(activity, "Error initializing biometric prompt", Toast.LENGTH_SHORT).show()
            onError()
        }
    )
}
private fun createBioAuthManager(context: android.content.Context): BioAuthManager {
    return BioAuthManager.Builder(context, MyBioAuthSettings(context)).build()
}