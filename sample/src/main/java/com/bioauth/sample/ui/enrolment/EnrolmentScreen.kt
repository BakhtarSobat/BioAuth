package com.bioauth.sample.ui.enrolment

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.bioauth.sample.ui.SecondaryButton
import com.bioauth.sample.ui.login.PinView

@Composable
fun LoggedInScreen(onLogout: () -> Unit) {
    val context = LocalContext.current
    val viewModel: EnrolmentViewModel = viewModel { EnrolmentViewModel(context) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = "Profile",
            style = MaterialTheme.typography.headlineMedium
        )

        PinEnrolmentSection(viewModel)

        Spacer(modifier = Modifier.height(16.dp))

        BiometricEnrolmentSection(viewModel)

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = {
                viewModel.logout()
                onLogout()
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Logout")
        }
    }
}

@Composable
fun PinEnrolmentSection(viewModel: EnrolmentViewModel) {
    val pinStatus by viewModel.pinEnrolmentStateFlow.collectAsState()
    viewModel.getPinEnrolmentState()
    Card(
        modifier = Modifier
            .fillMaxWidth(),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(4.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = when (val status = pinStatus) {
                    is EnrolmentViewModel.PinEnrolmentState.Error -> "Error: ${status.error}"
                    EnrolmentViewModel.PinEnrolmentState.Idle -> "Idle"
                    EnrolmentViewModel.PinEnrolmentState.Loading -> "Loading..."
                    is EnrolmentViewModel.PinEnrolmentState.Success -> "PIN enrolled"
                    EnrolmentViewModel.PinEnrolmentState.Unenrolled -> "PIN not enrolled"
                },
                style = MaterialTheme.typography.bodyMedium
            )
            when (pinStatus) {
                is EnrolmentViewModel.PinEnrolmentState.Error -> Text("Error: ${(pinStatus as EnrolmentViewModel.PinEnrolmentState.Error).error}")
                EnrolmentViewModel.PinEnrolmentState.Idle -> Text("Idle")
                EnrolmentViewModel.PinEnrolmentState.Loading -> Text("Loading...")
                is EnrolmentViewModel.PinEnrolmentState.Success -> {
                    SecondaryButton(
                        text = "Disable PIN",
                        onClick = {
                            viewModel.unenrollPin()
                        },
                        modifier = Modifier.fillMaxWidth()
                    )
                }

                EnrolmentViewModel.PinEnrolmentState.Unenrolled -> {
                    PinView(
                        loginWithPin = { pin ->
                            viewModel.enrollPin(pin)
                        }
                    )
                }
            }
        }
    }
}

@Composable
fun BiometricEnrolmentSection(viewModel: EnrolmentViewModel) {
    val biometricStatus by viewModel.bioEnrolmentStateFlow.collectAsState()
    viewModel.getBiometricEnrolmentState()
    Card(
        modifier = Modifier
            .fillMaxWidth(),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(0.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = when (val status = biometricStatus) {
                    is EnrolmentViewModel.BioEnrolmentState.Error -> "Error: ${status.error}"
                    EnrolmentViewModel.BioEnrolmentState.Idle -> "Idle"
                    EnrolmentViewModel.BioEnrolmentState.Loading -> "Loading..."
                    is EnrolmentViewModel.BioEnrolmentState.Success -> "Fingerprint enrolled"
                    EnrolmentViewModel.BioEnrolmentState.Unenrolled -> "Fingerprint not enrolled"
                },
                style = MaterialTheme.typography.bodyMedium
            )

            when (biometricStatus) {
                is EnrolmentViewModel.BioEnrolmentState.Error -> Unit
                EnrolmentViewModel.BioEnrolmentState.Idle -> Unit
                EnrolmentViewModel.BioEnrolmentState.Loading -> Unit
                is EnrolmentViewModel.BioEnrolmentState.Success -> {
                    SecondaryButton(
                        text = "Disable Fingerprint",
                        onClick = {
                            viewModel.unenrollFingerprint()
                        },
                        modifier = Modifier.fillMaxWidth()
                    )
                }

                EnrolmentViewModel.BioEnrolmentState.Unenrolled -> {
                    SecondaryButton(
                        text = "Enroll Fingerprint",
                        onClick = {
                            viewModel.enrollFingerprint()
                        },
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }
    }
}
