package com.bioauth.lib.manager

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.*
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.Executor
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

private const val ANDROID_KEY_STORE = "AndroidKeyStore"

interface IBioAuthManager {
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

    suspend fun isFingerEnabled(): Result<BioAuthSettings.BiometricStatus>
    suspend fun enableFingerPrint(status: BioAuthSettings.BiometricStatus): Result<Unit>
    suspend fun enroll(): Result<String>
    suspend fun promptBiometrics(promptData: PromptData, callback: BiometricsPromptCallback): Result<Boolean>
    fun stopListening()
    suspend fun getPublicKey(): Result<PublicKey>
    fun resetAll()
    fun getBiometricsState(authenticators: Int): AuthenticationTypes
    suspend fun promptBiometricsAndSign(
        promptData: PromptData,
        challenge: SignableObject,
        callback: SigningCallback
    ): Result<Boolean>

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

class BioAuthManager private constructor(
    private val context: Context,
    private val settings: BioAuthSettings,
    private val config: Config
) : IBioAuthManager {

    private val lock = ReentrantReadWriteLock()
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val keyGenerator by lazy {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE)
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

    override fun getBiometricsState(authenticators: Int): IBioAuthManager.AuthenticationTypes {
        return when (fingerprintManager.canAuthenticate(authenticators)) {
            BiometricManager.BIOMETRIC_SUCCESS -> IBioAuthManager.AuthenticationTypes.SUCCESS
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> IBioAuthManager.AuthenticationTypes.NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> IBioAuthManager.AuthenticationTypes.HARDWARE_UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> IBioAuthManager.AuthenticationTypes.NONE_ENROLLED
            else -> IBioAuthManager.AuthenticationTypes.UNKNOWN
        }
    }

    override suspend fun isFingerEnabled(): Result<BioAuthSettings.BiometricStatus> = withContext(Dispatchers.IO) {
        runCatching {
            lock.read {
                val enabled = settings.isEnabled()
                val publicKeyId = settings.getPublicKeyId()

                if (publicKeyId.isNullOrEmpty()) {
                    BioAuthSettings.BiometricStatus.Disabled
                } else {
                    enabled
                }
            }
        }
    }

    override suspend fun enableFingerPrint(status: BioAuthSettings.BiometricStatus): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            lock.write {
                settings.setBiometricStatus(status)
            }
        }
    }

    private suspend fun createKeyPair(): Result<KeyPair> = withContext(Dispatchers.IO) {
        runCatching {
            KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

            val keyGenSpec = KeyGenParameterSpec.Builder(
                config.keyStoreName,
                KeyProperties.PURPOSE_SIGN
            )
                .setDigests(config.digest)
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
                    onSuccess = { publicKey -> Result.success(publicKey.toPEM()) },
                    onFailure = { Result.failure(it) }
                )
            },
            onFailure = { Result.failure(it) }
        )
    }

    private suspend fun initCryptoObject(): Result<BiometricPrompt.CryptoObject> = withContext(Dispatchers.IO) {
        initSignature().fold(
            onSuccess = { signature -> Result.success(BiometricPrompt.CryptoObject(signature)) },
            onFailure = { error ->
                when (error) {
                    is KeyPermanentlyInvalidatedException -> {
                        enableFingerPrint(BioAuthSettings.BiometricStatus.Disabled)
                        Result.failure(FingerprintKeyChangedException())
                    }
                    else -> Result.failure(error)
                }
            }
        )
    }

    override suspend fun promptBiometricsAndSign(
        promptData: IBioAuthManager.PromptData,
        challenge: SignableObject,
        callback: IBioAuthManager.SigningCallback
    ): Result<Boolean> = withContext(Dispatchers.Main) {
        runCatching {
            val authenticationCallback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    callback.onSigningError(errorCode, errString.toString())
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    // Use the authenticated signature from the result
                    result.cryptoObject?.signature?.let { authenticatedSignature ->
                        scope.launch {
                            when (val signingResult = challenge.sign(authenticatedSignature)) {
                                is IBioAuthManager.SigningResult.Success -> {
                                    callback.onSigningSuccess(signingResult.signature)
                                }
                                is IBioAuthManager.SigningResult.BiometricKeyChanged -> {
                                    enableFingerPrint(BioAuthSettings.BiometricStatus.Disabled)
                                    callback.onSigningError(-1, "Biometric key has changed")
                                }
                                is IBioAuthManager.SigningResult.Error -> {
                                    callback.onSigningError(-1, signingResult.message)
                                }
                            }
                        }
                    } ?: run {
                        callback.onSigningError(-1, "No authenticated signature available")
                    }
                }

                override fun onAuthenticationFailed() {
                    callback.onSigningError(-1, "Authentication failed")
                }
            }

            biometricPrompt = when {
                promptData.fragment != null ->
                    BiometricPrompt(promptData.fragment, promptData.executor, authenticationCallback)
                promptData.fragmentActivity != null ->
                    BiometricPrompt(promptData.fragmentActivity, promptData.executor, authenticationCallback)
                else -> throw IllegalArgumentException("Either fragment or fragmentActivity must be provided")
            }

            val cryptoObject = initCryptoObject().getOrThrow()
            biometricPrompt?.authenticate(promptData.info, cryptoObject)
            true
        }
    }

    private suspend fun initSignature(): Result<Signature> = withContext(Dispatchers.IO) {
        runCatching {
            val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
            val key = keyStore.getKey(config.keyStoreName, null) as PrivateKey
            val signature = Signature.getInstance(config.algorithm)
            signature.initSign(key)
            signature
        }
    }

    override suspend fun promptBiometrics(
        promptData: IBioAuthManager.PromptData,
        callback: IBioAuthManager.BiometricsPromptCallback
    ): Result<Boolean> = withContext(Dispatchers.Main) {
        runCatching {
            val authenticationCallback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    callback.onAuthenticationError(errorCode, errString)
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    callback.onAuthenticationSucceeded(result)
                }

                override fun onAuthenticationFailed() {
                    callback.onAuthenticationFailed()
                }
            }

            biometricPrompt = when {
                promptData.fragment != null ->
                    BiometricPrompt(promptData.fragment, promptData.executor, authenticationCallback)
                promptData.fragmentActivity != null ->
                    BiometricPrompt(promptData.fragmentActivity, promptData.executor, authenticationCallback)
                else -> throw IllegalArgumentException("Either fragment or fragmentActivity must be provided")
            }

            val cryptoObject = initCryptoObject().getOrThrow()
            biometricPrompt?.authenticate(promptData.info, cryptoObject)
            true
        }
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
            enableFingerPrint(BioAuthSettings.BiometricStatus.Unknown)
        }
    }


    class FingerprintKeyChangedException : Exception("Fingerprint key has been changed")

    class Builder(private val context: Context, private val settings: BioAuthSettings) {
        private var config = Config()

        fun withDigest(digest: String) = apply {
            config = config.copy(digest = digest)
        }

        fun withAlgorithm(algorithm: String) = apply {
            config = config.copy(algorithm = algorithm)
        }

        fun withKeyStoreName(name: String) = apply {
            config = config.copy(keyStoreName = name)
        }

        fun withECGenParameterSpec(ecGenParam: ECGenParameterSpec) = apply {
            config = config.copy(ecGenParameterSpec = ecGenParam)
        }

        fun build() = BioAuthManager(context, settings, config)
    }
}

private fun PublicKey.toPEM(): String {
    val encodedKey = Base64.encodeToString(encoded, Base64.DEFAULT)
    return "-----BEGIN PUBLIC KEY-----\n$encodedKey-----END PUBLIC KEY-----"
}



