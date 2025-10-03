package com.bioauth.lib.manager.authentication.biometrics

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import com.bioauth.lib.manager.authentication.AuthenticationSettings
import com.bioauth.lib.manager.authentication.SignableObject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.Executor

private const val ANDROID_KEY_STORE = "AndroidKeyStore"

interface BiometricAuthenticationManager {
    sealed class SigningResult {
        data class Success(val signature: String) : SigningResult()
        data class Error(val message: String) : SigningResult()
        data object BiometricKeyChanged : SigningResult()
    }

    data class PromptData(
        val info: BiometricPrompt.PromptInfo,
        val executor: Executor,
        val fragment: Fragment?,
        val fragmentActivity: FragmentActivity?
    )

    suspend fun getBiometricEnrolmentStatus(): AuthenticationSettings.EnrolmentStatus
    fun setBiometricEnrolmentStatus(status: AuthenticationSettings.EnrolmentStatus)
    suspend fun enroll(): Result<String>
    fun promptBiometrics(
        promptData: PromptData,
        callback: BiometricsPromptCallback
    )

    fun stopListening()
    suspend fun getPublicKey(): Result<PublicKey>
    fun resetAll()
    fun getBiometricsState(authenticators: Int): AuthenticationTypes
    fun promptBiometricsAndSign(
        promptData: PromptData,
        challenge: SignableObject,
        callback: SigningCallback
    )

    interface SigningCallback {
        fun onSigningSuccess(signature: String)
        fun onSigningError(errorCode: Int, message: String)
    }

    enum class AuthenticationTypes {
        SUCCESS,
        NO_HARDWARE,
        HARDWARE_UNAVAILABLE,
        NONE_ENROLLED,
        UNKNOWN
    }

    interface BiometricsPromptCallback {
        fun onAuthenticationError(errorCode: Int, errString: CharSequence)
        fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult)
        fun onAuthenticationFailed()
    }
}

internal class BiometricAuthenticationManagerImpl(
    private val context: Context,
    private val settings: AuthenticationSettings,
    private val config: Config,
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
) : BiometricAuthenticationManager {

    private val keyGenerator by lazy<KeyPairGenerator> {
        KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEY_STORE
        ) // Hardware-based EC key generation
    }

    private val fingerprintManager by lazy { BiometricManager.from(context) }

    @Volatile
    private var biometricPrompt: BiometricPrompt? = null

    data class Config(
        val digest: String = KeyProperties.DIGEST_SHA256,
        val algorithm: String = "SHA256withECDSA",
        val keyStoreName: String = "bioauthKey",
        val ecGenParameterSpec: ECGenParameterSpec = ECGenParameterSpec("secp256r1")
    )

    override fun getBiometricsState(authenticators: Int): BiometricAuthenticationManager.AuthenticationTypes {
        return when (fingerprintManager.canAuthenticate(authenticators)) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricAuthenticationManager.AuthenticationTypes.SUCCESS
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricAuthenticationManager.AuthenticationTypes.NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricAuthenticationManager.AuthenticationTypes.HARDWARE_UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricAuthenticationManager.AuthenticationTypes.NONE_ENROLLED
            else -> BiometricAuthenticationManager.AuthenticationTypes.UNKNOWN
        }
    }

    override suspend fun getBiometricEnrolmentStatus(): AuthenticationSettings.EnrolmentStatus =
        withContext(Dispatchers.IO) {
            val enabled = settings.getEnrolmentStatus()
            val publicKeyId = settings.getPublicKeyId()

            if (enabled == AuthenticationSettings.EnrolmentStatus.Enabled == !publicKeyId.isNullOrEmpty()) {
                AuthenticationSettings.EnrolmentStatus.Enabled
            } else {
                enabled
            }
        }

    override fun setBiometricEnrolmentStatus(status: AuthenticationSettings.EnrolmentStatus) {
        scope.launch {
            settings.setEnrolmentStatus(status)
        }
    }

    private suspend fun createKeyPair(): Result<KeyPair> = withContext(Dispatchers.IO) {
        runCatching {
            KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
            val keyGenSpec = KeyGenParameterSpec.Builder(
                config.keyStoreName,
                KeyProperties.PURPOSE_SIGN
            ).setDigests(config.digest)
                .setAlgorithmParameterSpec(config.ecGenParameterSpec)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .build()
            keyGenerator.initialize(keyGenSpec)
            keyGenerator.generateKeyPair()
        }
    }

    override suspend fun enroll(): Result<String> = withContext(Dispatchers.IO) {
        createKeyPair().fold(
            onSuccess = {
                getPublicKey().fold(
                    onSuccess = { publicKey ->
                        settings.setEnrolmentStatus(AuthenticationSettings.EnrolmentStatus.Enabled)
                        settings.storePublicKeyId(config.keyStoreName)
                        Result.success(publicKey.toPEM())
                    },
                    onFailure = { Result.failure(it) }
                )
            },
            onFailure = { Result.failure(it) }
        )
    }

    private fun initCryptoObject(): Result<BiometricPrompt.CryptoObject> {
        return initSignature().fold(
            onSuccess = { signature -> Result.success(BiometricPrompt.CryptoObject(signature)) },
            onFailure = { error ->
                when (error) {
                    is KeyPermanentlyInvalidatedException -> {
                        setBiometricEnrolmentStatus(AuthenticationSettings.EnrolmentStatus.Disabled)
                        Result.failure(FingerprintKeyChangedException())
                    }

                    else -> Result.failure(error)
                }
            }
        )
    }

    override fun promptBiometricsAndSign(
        promptData: BiometricAuthenticationManager.PromptData,
        challenge: SignableObject,
        callback: BiometricAuthenticationManager.SigningCallback
    ) {
        val authenticationCallback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                callback.onSigningError(errorCode, errString.toString())
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                // Use the authenticated signature from the result
                signChallenge(result, challenge, callback)
            }

            override fun onAuthenticationFailed() {
                callback.onSigningError(-1, "Authentication failed")
            }
        }

        biometricPrompt = when {
            promptData.fragment != null ->
                BiometricPrompt(
                    promptData.fragment,
                    promptData.executor,
                    authenticationCallback
                )

            promptData.fragmentActivity != null ->
                BiometricPrompt(
                    promptData.fragmentActivity,
                    promptData.executor,
                    authenticationCallback
                )

            else -> throw IllegalArgumentException("Either fragment or fragmentActivity must be provided")
        }

        initCryptoObject().fold(
            onSuccess = { biometricPrompt?.authenticate(promptData.info, it) },
            onFailure = {
                callback.onSigningError(
                    -1,
                    it.message ?: "Unknown error initializing crypto object"
                )
                return
            }
        )
    }


    private fun signChallenge(
        result: BiometricPrompt.AuthenticationResult,
        challenge: SignableObject,
        callback: BiometricAuthenticationManager.SigningCallback
    ) {
        result.cryptoObject?.signature?.let { authenticatedSignature ->
            when (val signingResult = challenge.sign(authenticatedSignature)) {
                is BiometricAuthenticationManager.SigningResult.Success -> {
                    callback.onSigningSuccess(signingResult.signature)
                }

                is BiometricAuthenticationManager.SigningResult.BiometricKeyChanged -> {
                    setBiometricEnrolmentStatus(AuthenticationSettings.EnrolmentStatus.Disabled)
                    callback.onSigningError(-1, "Biometric key has changed")
                }

                is BiometricAuthenticationManager.SigningResult.Error -> {
                    callback.onSigningError(-1, signingResult.message)
                }
            }

        } ?: run {
            callback.onSigningError(-1, "No authenticated signature available")
        }
    }

    private fun initSignature(): Result<Signature> {
        return runCatching {
            val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
            val key = keyStore.getKey(config.keyStoreName, null) as PrivateKey
            val signature = Signature.getInstance(config.algorithm)
            signature.initSign(key)
            signature
        }
    }

    override fun promptBiometrics(
        promptData: BiometricAuthenticationManager.PromptData,
        callback: BiometricAuthenticationManager.BiometricsPromptCallback
    ) {
        val authenticationCallback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) =
                callback.onAuthenticationError(errorCode, errString)

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) =
                callback.onAuthenticationSucceeded(result)

            override fun onAuthenticationFailed() = callback.onAuthenticationFailed()
        }

        biometricPrompt = when {
            promptData.fragment != null ->
                BiometricPrompt(
                    promptData.fragment,
                    promptData.executor,
                    authenticationCallback
                )

            promptData.fragmentActivity != null ->
                BiometricPrompt(
                    promptData.fragmentActivity,
                    promptData.executor,
                    authenticationCallback
                )

            else -> throw IllegalArgumentException("Either fragment or fragmentActivity must be provided")
        }

        initCryptoObject().fold(
            onSuccess = { cryptoObject ->
                biometricPrompt?.authenticate(promptData.info, cryptoObject)
            },
            onFailure = {
                callback.onAuthenticationError(
                    -1,
                    it.message ?: "Unknown error initializing crypto object"
                )
                return
            }
        )
    }

    override fun stopListening() {
        biometricPrompt = null
    }

    override suspend fun getPublicKey(): Result<PublicKey> = withContext(Dispatchers.IO) {
        runCatching {
            val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
            keyStore.getCertificate(config.keyStoreName).publicKey
        }
    }

    override fun resetAll() {
        runBlocking {
            setBiometricEnrolmentStatus(AuthenticationSettings.EnrolmentStatus.Unknown)
        }
    }


    class FingerprintKeyChangedException : Exception("Fingerprint key has been changed")

}

private fun PublicKey.toPEM(): String {
    val encodedKey = Base64.encodeToString(encoded, Base64.DEFAULT)
    return "-----BEGIN PUBLIC KEY-----\n$encodedKey-----END PUBLIC KEY-----"
}



