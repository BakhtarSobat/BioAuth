package com.bioauth.sample.ui.enrolment

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.bioauth.lib.manager.authentication.AuthenticationSettings
import com.bioauth.lib.manager.authentication.biometrics.BiometricAuthenticationManager
import com.bioauth.lib.manager.authentication.biometrics.builder.biometricAuthenticationManager
import com.bioauth.lib.manager.authentication.password.PasswordAuthenticationManager
import com.bioauth.lib.manager.authentication.password.builder.passwordAuthenticationManager
import com.bioauth.sample.MyBioAuthSettings
import com.bioauth.sample.MyPasswordAuthSettings
import com.bioauth.sample.manager.AuthenticationManager
import com.bioauth.sample.repository.AuthenticationRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class EnrolmentViewModel(
    context: Context,
    private val biometricAuthenticationManagerImpl: BiometricAuthenticationManager = biometricAuthenticationManager(
        context = context,
        MyBioAuthSettings(context)
    ),
    private val passwordAuthManager: PasswordAuthenticationManager = passwordAuthenticationManager(
        settings = MyPasswordAuthSettings(context)
    ),
    private val authenticationRepository: AuthenticationRepository = AuthenticationRepository(
        context
    ),
    private val authenticationManager: AuthenticationManager = AuthenticationManager
) : ViewModel() {

    sealed interface BioEnrolmentState {
        object Idle : BioEnrolmentState
        object Loading : BioEnrolmentState
        object Unenrolled : BioEnrolmentState
        data class Success(val message: String) : BioEnrolmentState
        data class Error(val error: String) : BioEnrolmentState
    }

    sealed interface PinEnrolmentState {
        object Idle : PinEnrolmentState
        object Loading : PinEnrolmentState
        object Unenrolled : PinEnrolmentState
        data class Success(val message: String) : PinEnrolmentState
        data class Error(val error: String) : PinEnrolmentState
    }

    private val _bioEnrolmentStateFlow: MutableStateFlow<BioEnrolmentState> =
        MutableStateFlow(BioEnrolmentState.Idle)
    val bioEnrolmentStateFlow: MutableStateFlow<BioEnrolmentState> = _bioEnrolmentStateFlow

    private val _pinEnrolmentStateFlow: MutableStateFlow<PinEnrolmentState> =
        MutableStateFlow(PinEnrolmentState.Idle)
    val pinEnrolmentStateFlow: MutableStateFlow<PinEnrolmentState> = _pinEnrolmentStateFlow

    fun getPinEnrolmentState() {
        viewModelScope.launch {
            pinEnrolmentStateFlow.value = PinEnrolmentState.Loading
            when (passwordAuthManager.getPasswordEnrolmentStatus()) {
                AuthenticationSettings.EnrolmentStatus.Enabled -> {
                    pinEnrolmentStateFlow.value = PinEnrolmentState.Success("PIN is enrolled")
                }

                AuthenticationSettings.EnrolmentStatus.Disabled -> {
                    pinEnrolmentStateFlow.value = PinEnrolmentState.Unenrolled
                }

                AuthenticationSettings.EnrolmentStatus.Unknown -> {
                    pinEnrolmentStateFlow.value = PinEnrolmentState.Unenrolled
                }
            }
        }
    }

    fun getBiometricEnrolmentState() {
        viewModelScope.launch {
            bioEnrolmentStateFlow.value = BioEnrolmentState.Loading
            when (biometricAuthenticationManagerImpl.getBiometricEnrolmentStatus()) {
                AuthenticationSettings.EnrolmentStatus.Enabled -> {
                    bioEnrolmentStateFlow.value =
                        BioEnrolmentState.Success("Fingerprint is enrolled")
                }

                AuthenticationSettings.EnrolmentStatus.Disabled -> {
                    bioEnrolmentStateFlow.value = BioEnrolmentState.Unenrolled
                }

                AuthenticationSettings.EnrolmentStatus.Unknown -> {
                    bioEnrolmentStateFlow.value = BioEnrolmentState.Unenrolled
                }
            }
        }
    }

    fun enrollFingerprint() {
        viewModelScope.launch {
            biometricAuthenticationManagerImpl.enroll().fold(
                onSuccess = { publicKey ->
                    authenticationRepository.enrolAuthenticationPublicKey("bio", publicKey)
                    bioEnrolmentStateFlow.value = BioEnrolmentState.Success("Enrollment successful")
                },
                onFailure = { error ->
                    bioEnrolmentStateFlow.value =
                        BioEnrolmentState.Error("Enrollment failed: ${error.message}")
                }
            )
        }
    }

    fun unenrollFingerprint() {
        viewModelScope.launch {
            biometricAuthenticationManagerImpl.setBiometricEnrolmentStatus(AuthenticationSettings.EnrolmentStatus.Unknown)
            _bioEnrolmentStateFlow.value =
                when (biometricAuthenticationManagerImpl.getBiometricEnrolmentStatus()) {
                    AuthenticationSettings.EnrolmentStatus.Disabled -> BioEnrolmentState.Unenrolled
                    AuthenticationSettings.EnrolmentStatus.Enabled -> BioEnrolmentState.Success("Fingerprint is enrolled")
                    AuthenticationSettings.EnrolmentStatus.Unknown -> BioEnrolmentState.Unenrolled
                }
        }
    }

    fun logout() {
        viewModelScope.launch {
            authenticationManager.setLoading()
            authenticationManager.resetState()
        }
    }

    fun unenrollPin() {
        viewModelScope.launch {
            passwordAuthManager.setPasswordEnrolmentStatus(AuthenticationSettings.EnrolmentStatus.Unknown)
            _pinEnrolmentStateFlow.value = when (passwordAuthManager.getPasswordEnrolmentStatus()) {
                AuthenticationSettings.EnrolmentStatus.Disabled -> PinEnrolmentState.Unenrolled
                AuthenticationSettings.EnrolmentStatus.Enabled -> PinEnrolmentState.Success("PIN is enrolled")
                AuthenticationSettings.EnrolmentStatus.Unknown -> PinEnrolmentState.Unenrolled
            }
        }
    }

    fun enrollPin(pin: String) {
        viewModelScope.launch {
            passwordAuthManager.enroll(pin).fold(
                onSuccess = {
                    authenticationRepository.enrolAuthenticationPublicKey("pin", it)
                    pinEnrolmentStateFlow.value =
                        PinEnrolmentState.Success("PIN enrollment successful")
                },
                onFailure = { error ->
                    pinEnrolmentStateFlow.value =
                        PinEnrolmentState.Error("PIN enrollment failed: ${error.message}")
                }
            )
        }
    }
}