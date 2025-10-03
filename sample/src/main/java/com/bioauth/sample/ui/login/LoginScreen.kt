package com.bioauth.sample.ui.login

import android.widget.Toast
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.viewmodel.compose.viewModel
import com.bioauth.sample.R
import com.bioauth.sample.manager.AuthenticationManager.AuthenticationState
import com.bioauth.sample.ui.SecondaryButton
import com.bioauth.sample.ui.login.LoginViewModel.BiometricStatus
import com.bioauth.sample.ui.login.LoginViewModel.PinStatus


@Composable
fun LoginScreen(
    onEnrol: () -> Unit,
) {
    val context = LocalContext.current
    val activity = context as FragmentActivity
    val viewModel: LoginViewModel = viewModel { LoginViewModel(context) }

    val authenticationStatus by viewModel.authenticationStateFlow.collectAsState(AuthenticationState.Idle)

    val biometricEnrolmentStatus by viewModel.biometricEnrolmentStateFlow.collectAsState(initial = BiometricStatus.Unknown)
    viewModel.getBiometricEnrolmentStatus()

    val pinEnrolmentStatus by viewModel.pinEnrolmentStateFlow.collectAsState(initial = PinStatus.Unknown)
    viewModel.getPinEnrolmentStatus()

    when(val status = authenticationStatus){
        is AuthenticationState.Error -> Toast.makeText(context, status.error, Toast.LENGTH_SHORT).show()
        AuthenticationState.Idle -> Unit
        AuthenticationState.Loading -> Toast.makeText(context, "Loading...", Toast.LENGTH_SHORT).show()
        is AuthenticationState.Success -> onEnrol()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {

        PinSection(
            pintStatus = pinEnrolmentStatus,
            enrolPin = { pin ->
                viewModel.loginWithPin(pin)
            }
        )
        Spacer(modifier = Modifier.height(32.dp))
        FingerprintSection(
            state = biometricEnrolmentStatus,
            onFingerprintClick = {
                viewModel.showFingerprintDialog(activity)
            }
        )

        Spacer(modifier = Modifier.height(16.dp))
        if(pinEnrolmentStatus != PinStatus.Enrolled && biometricEnrolmentStatus != BiometricStatus.Available){
            Text("Enrol biometrics or PIN to login")
            Button(
                onClick = {
                    onEnrol()
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 16.dp)
            ) {
                Text("Setup Authentication")
            }
        }
    }
}

@Composable
fun PinSection(pintStatus: PinStatus, enrolPin: (String) -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(8.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
    ) {
        Column(
            modifier = Modifier.padding(8.dp)
                .fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Text(
                text = "PIN Authentication",
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.padding(bottom = 16.dp)
            )
            when (pintStatus) {
                PinStatus.Enrolled -> PinView {
                    enrolPin(it)
                }

                PinStatus.NotSet, PinStatus.Unknown -> Text("PIN not set")
            }
        }
    }
}

@Composable
fun PinView(loginWithPin: (String) -> Unit) {
    var pin by remember { mutableStateOf("") }

        Column(
            modifier = Modifier
                .fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {

            OutlinedTextField(
                value = pin,
                onValueChange = { newValue ->
                    if (newValue.all { it.isDigit() }) {
                        pin = newValue
                    }
                },
                label = { Text("Enter PIN") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth()
            )

            SecondaryButton(
                text = "Login",
                onClick = {
                    loginWithPin(pin)
                },
                modifier = Modifier.fillMaxWidth()
            )
        }

}

@Composable
fun FingerprintSection(
    state: BiometricStatus,
    onFingerprintClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(8.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
    ) {
        Column(
            modifier = Modifier.padding(8.dp)
                .fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "Biometric Authentication",
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.padding(bottom = 16.dp)
            )
            Image(
                painter = painterResource(
                    when (state) {
                        BiometricStatus.Available -> R.drawable.ic_fingerprint
                        BiometricStatus.NotEnrolled -> R.drawable.ic_error
                        is BiometricStatus.Unavailable -> R.drawable.ic_error
                        BiometricStatus.Unknown -> R.drawable.ic_error
                    }
                ),
                contentDescription = "Fingerprint",
                modifier = Modifier
                    .size(64.dp)
                    .clickable(enabled = state == BiometricStatus.Available) {
                        onFingerprintClick()
                    }
            )

            Text(
                text = when (state) {
                    BiometricStatus.Available -> "Login with Fingerprint"
                    BiometricStatus.NotEnrolled -> "Fingerprint not enrolled"
                    is BiometricStatus.Unavailable -> state.message
                    BiometricStatus.Unknown -> "Biometric status unknown"
                },
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}
