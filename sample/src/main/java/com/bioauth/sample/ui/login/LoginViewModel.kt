package com.bioauth.sample.ui.login

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.bioauth.lib.manager.authentication.AuthenticationSettings
import com.bioauth.lib.manager.authentication.biometrics.BiometricAuthenticationManager
import com.bioauth.lib.manager.authentication.biometrics.builder.biometricAuthenticationManager
import com.bioauth.lib.manager.authentication.password.PasswordAuthenticationManager
import com.bioauth.lib.manager.authentication.password.builder.passwordAuthenticationManager
import com.bioauth.sample.MyBioAuthSettings
import com.bioauth.sample.MyPasswordAuthSettings
import com.bioauth.sample.MySignableObject
import com.bioauth.sample.manager.AuthenticationManager
import com.bioauth.sample.manager.AuthenticationManager.AuthenticationState
import com.bioauth.sample.repository.AuthenticationRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import java.util.Random
import java.util.concurrent.Executor

private const val SALT = "SUPER_SALT"
class LoginViewModel(
    context: Context,
    private val biometricAuthenticationManagerImpl: BiometricAuthenticationManager = biometricAuthenticationManager(context, MyBioAuthSettings(context)),
    private val passwordAuthManager: PasswordAuthenticationManager = passwordAuthenticationManager(MyPasswordAuthSettings(context)),
    private val authenticationRepository: AuthenticationRepository = AuthenticationRepository(context),
    private val authenticationManager: AuthenticationManager = AuthenticationManager
) : ViewModel() {

    sealed interface PinStatus{
        object Enrolled: PinStatus
        object NotSet: PinStatus
        object Unknown: PinStatus
    }
    sealed interface BiometricStatus{
        object Available: BiometricStatus
        data class Unavailable(val message: String): BiometricStatus
        object NotEnrolled: BiometricStatus
        object Unknown: BiometricStatus
    }
    private val _biometricEnrolmentStateFlow: MutableStateFlow<BiometricStatus> = MutableStateFlow(BiometricStatus.Unknown)
    val biometricEnrolmentStateFlow: Flow<BiometricStatus> = _biometricEnrolmentStateFlow
    private val _pinEnrolmentStateFlow: MutableStateFlow<PinStatus> = MutableStateFlow(PinStatus.Unknown)
    val pinEnrolmentStateFlow: Flow<PinStatus> = _pinEnrolmentStateFlow

    val authenticationStateFlow: Flow<AuthenticationState> = authenticationManager.authenticationStateFlow

    fun getPinEnrolmentStatus(){
        viewModelScope.launch {
            when(passwordAuthManager.getPasswordEnrolmentStatus()){
                AuthenticationSettings.EnrolmentStatus.Enabled -> _pinEnrolmentStateFlow.value = PinStatus.Enrolled
                AuthenticationSettings.EnrolmentStatus.Disabled -> _pinEnrolmentStateFlow.value = PinStatus.NotSet
                AuthenticationSettings.EnrolmentStatus.Unknown -> _pinEnrolmentStateFlow.value = PinStatus.Unknown
            }
        }
    }

    fun getBiometricEnrolmentStatus(){
        viewModelScope.launch {
            when(biometricAuthenticationManagerImpl.getBiometricsState(BiometricManager.Authenticators.BIOMETRIC_STRONG)){
                BiometricAuthenticationManager.AuthenticationTypes.SUCCESS -> {
                    getBioEnrolmentStatus()
                }
                BiometricAuthenticationManager.AuthenticationTypes.NO_HARDWARE -> _biometricEnrolmentStateFlow.value = BiometricStatus.Unavailable("No biometric hardware")
                BiometricAuthenticationManager.AuthenticationTypes.HARDWARE_UNAVAILABLE -> _biometricEnrolmentStateFlow.value = BiometricStatus.Unavailable("Biometric hardware unavailable")
                BiometricAuthenticationManager.AuthenticationTypes.NONE_ENROLLED -> _biometricEnrolmentStateFlow.value = BiometricStatus.Unavailable("None device fingerprint enrolled")
                BiometricAuthenticationManager.AuthenticationTypes.UNKNOWN -> _biometricEnrolmentStateFlow.value = BiometricStatus.Unknown
            }
        }
    }

    private suspend fun getBioEnrolmentStatus(){
        when(biometricAuthenticationManagerImpl.getBiometricEnrolmentStatus()){
            AuthenticationSettings.EnrolmentStatus.Disabled -> _biometricEnrolmentStateFlow.value = BiometricStatus.Unavailable("Biometric is disabled")
            AuthenticationSettings.EnrolmentStatus.Enabled -> _biometricEnrolmentStateFlow.value = BiometricStatus.Available
            AuthenticationSettings.EnrolmentStatus.Unknown -> _biometricEnrolmentStateFlow.value = BiometricStatus.NotEnrolled
        }
    }

    fun showFingerprintDialog(
        activity: FragmentActivity
    ) {
        viewModelScope.launch {

            val executor = ContextCompat.getMainExecutor(activity)
            val promptData = createPromptData(executor, activity)

            val signable = getChallenge()

            biometricAuthenticationManagerImpl.promptBiometricsAndSign(
                promptData,
                signable,
                object : BiometricAuthenticationManager.SigningCallback {
                    override fun onSigningSuccess(signature: String) {
                        verifyWithBackend(keyId = "bio", signature, signable)
                    }
                    override fun onSigningError(errorCode: Int, message: String) {
                        authenticationManager.setError("Signing error: $message")
                    }
                }
            )
        }
    }

    private fun getChallenge(): MySignableObject {
        val challenge = authenticationRepository.getChallenge()
        val nonce = Random().nextInt(100)
        val stringToSign = "$challenge$SALT$nonce"
        val signable = MySignableObject(stringToSign, nonce)
        return signable
    }

    private fun verifyWithBackend(keyId: String, signature: String, signable: MySignableObject) {
        val verified = authenticationRepository.verify(keyId = keyId ,response = signature, nonce = signable.nonce)
        if (verified) {
            authenticationManager.setSuccess("Biometric login successful")
        } else {
            authenticationManager.setError("Challenge verification failed")
        }
    }

    fun loginWithPin(pin: String) {
        viewModelScope.launch {
            val signable = getChallenge()
            passwordAuthManager.signWithPassword(signable, pin).let { signingResult ->
                when (signingResult) {
                    is PasswordAuthenticationManager.SigningResult.Error -> {
                        authenticationManager.setError("Signing error: ${signingResult.message}")
                    }
                    PasswordAuthenticationManager.SigningResult.PasswordChanged -> {
                        authenticationManager.setError("Password changed, please login with password")
                    }
                    is PasswordAuthenticationManager.SigningResult.Success -> {
                        val signature = signingResult.signature
                        verifyWithBackend(keyId = "pin", signature, signable)
                    }
                }
            }
        }
    }

    private fun createPromptData(
        executor: Executor,
        activity: FragmentActivity
    ): BiometricAuthenticationManager.PromptData {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric login for my app")
            .setSubtitle("Log in using your biometric credential")
            .setNegativeButtonText("Use account password")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        val promptData = BiometricAuthenticationManager.PromptData(promptInfo, executor, null, activity)
        return promptData
    }

}

