package com.bioauth.lib.manager

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.core.os.CancellationSignal
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.Executor


private const val ANDROID_KEY_STORE = "AndroidKeyStore"

interface IBioAuthManager {
    data class PromptData(val info: BiometricPrompt.PromptInfo, val executor: Executor, val fragment: Fragment?, val fragmentActivity: FragmentActivity?)

    fun isFingerEnabled(): BioAuthSettings.BiometricStatus
    fun enableFingerPrint(status: BioAuthSettings.BiometricStatus)
    fun savePublicKeyId(publicKeyId: String)
    fun getPublicKeyId(): String?
    fun enroll(): BioAuthManager.PublicKeyPemResult
    fun signChallenge(challenge: SignableObject): BioAuthManager.SigningResult

    fun promptBiometrics( promptData: IBioAuthManager.PromptData, callBack: IBioAuthManager.BiometricsPromptCallBack): Boolean
    fun stopListening()
    fun getPublicKey(): BioAuthManager.PublicKeyResult
    fun checkSelfPermission(): Boolean
    fun resetAll()
    fun getBiometricsState(authenticators: Int): IBioAuthManager.AuthenticationTypes

    enum class AuthenticationTypes{
        SUCCESS,
        NO_HARDWARE,
        HARDWARE_UNAVAILABLE,
        NONE_ENROLLED,
        UNKNOWN

    }

    interface BiometricsPromptCallBack{
        fun onAuthenticationError(errorCode: Int, errString: CharSequence)
        fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult)
        fun onAuthenticationFailed()

    }
}

class BioAuthManager private constructor(private val context: Context, private val settings: BioAuthSettings) : IBioAuthManager {
    private lateinit var _ecGenParameterSpec: ECGenParameterSpec
    private lateinit var _digest: String
    private lateinit var _alg: String
    private lateinit var _keyStoreName: String

    private val keyGenerator by lazy { KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")}

    private val fingerprintManager by lazy { BiometricManager.from(context) }
    private val keyStore: KeyStore by lazy { KeyStore.getInstance(ANDROID_KEY_STORE) }
    private var cancellationSignal: CancellationSignal? = null
    private var selfCancelled: Boolean = false

    private val cryptoObject  by lazy { initCryptoObject() }

    override fun getBiometricsState(authenticators: Int): IBioAuthManager.AuthenticationTypes{
        return when (fingerprintManager.canAuthenticate(authenticators)) {
            BiometricManager.BIOMETRIC_SUCCESS -> IBioAuthManager.AuthenticationTypes.SUCCESS
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> IBioAuthManager.AuthenticationTypes.NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->IBioAuthManager.AuthenticationTypes.HARDWARE_UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> IBioAuthManager.AuthenticationTypes.NONE_ENROLLED
            else -> IBioAuthManager.AuthenticationTypes.UNKNOWN
        }
    }

    override fun isFingerEnabled(): BioAuthSettings.BiometricStatus{
        val enabled = settings.isEnabled()

        if(getPublicKeyId() == null || getPublicKeyId()!!.isEmpty()) return BioAuthSettings.BiometricStatus.Disabled

        return enabled

    }

    override fun enableFingerPrint(status: BioAuthSettings.BiometricStatus) {
        settings.setBiometricStatus(status)
    }

    override fun savePublicKeyId(publicKeyId: String){
        settings.storePublicKeyId(publicKeyId)
    }

    override fun getPublicKeyId(): String? = settings.getPublicKeyId()

    /**
     * Generates an asymmetric key pair in the Android Keystore. Every use of the private key must
     * be authorized by the user authenticating with fingerprint. Public key use is unrestricted.
     */
    private fun createKeyPair(): Boolean {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            keyStore.load(null)
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder
            keyGenerator.initialize(
                    KeyGenParameterSpec.Builder(_keyStoreName,
                            KeyProperties.PURPOSE_SIGN)
                            .setDigests(_digest)
                            .setAlgorithmParameterSpec(_ecGenParameterSpec)
                            // Require the user to authenticate with a fingerprint to authorize
                            // every use of the private key
                            .setUserAuthenticationRequired(true)
                            .setInvalidatedByBiometricEnrollment(true)
                            .build())
            keyGenerator.generateKeyPair()
            return true
        } catch (e: InvalidAlgorithmParameterException) {
            return false
        }
    }

    override fun enroll(): PublicKeyPemResult{
        return try {
            createKeyPair()
            when(val publicKey = getPublicKey()){
                is PublicKeyResult.Error -> PublicKeyPemResult.Error
                is PublicKeyResult.Result -> PublicKeyPemResult.Result(publicKey.publicKey.toPEM())
            }
        } catch (e: InvalidKeyException) {
            PublicKeyPemResult.Error
        }
    }

    private fun initCryptoObject(): CryptoObjectResult{
        val signatureToSign: SignatureResult = initSignature()

        return when(signatureToSign){
            is SignatureResult.Result -> {
                val cryptoObject = BiometricPrompt.CryptoObject(signatureToSign.signature)
                CryptoObjectResult.Result(cryptoObject)
            }
            is SignatureResult.Error -> {
                handleIntCryptoObjectError(signatureToSign.error)
            }
        }
    }

    private fun handleIntCryptoObjectError(error: Throwable?): CryptoObjectResult {
        return when(error){
            is FingerprintKeyChangedException -> {
                CryptoObjectResult.Error(error)
            }
            else -> {
                CryptoObjectResult.Error(null)
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun signChallenge(challenge: SignableObject): SigningResult {
        val obj = cryptoObject
        return when(obj){
            is BioAuthManager.CryptoObjectResult.Error -> SigningResult.Error
            is BioAuthManager.CryptoObjectResult.Result -> {
                val signature = obj.cryptoObject.signature?: return SigningResult.Error
                return challenge.sign(signature)
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun initSignature(): SignatureResult {
        try {
            keyStore.load(null)
            val key = keyStore.getKey(_keyStoreName, null) as PrivateKey?
            val signature = signature()
            signature.initSign(key)
            return SignatureResult.Result(signature)
        } catch (e: KeyPermanentlyInvalidatedException){
            enableFingerPrint(BioAuthSettings.BiometricStatus.Disabled)
            return SignatureResult.Error(FingerprintKeyChangedException())
        } catch (e: Exception) {
            enableFingerPrint(BioAuthSettings.BiometricStatus.Disabled)
        }
        return SignatureResult.Error(null);
    }

    private fun signature() = Signature.getInstance(_alg)

    override fun promptBiometrics( promptData: IBioAuthManager.PromptData, callBack: IBioAuthManager.BiometricsPromptCallBack): Boolean {
        val authenticationCallback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int,
                                               errString: CharSequence) {
                callBack.onAuthenticationError(errorCode, errString)
                super.onAuthenticationError(errorCode, errString)
            }

            override fun onAuthenticationSucceeded(
                result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                callBack.onAuthenticationSucceeded(result)
            }

            override fun onAuthenticationFailed() {
                callBack.onAuthenticationFailed()
                super.onAuthenticationFailed()
            }
        }

        val biometricPrompt = if(promptData.fragment != null) {
            BiometricPrompt(promptData.fragment, promptData.executor, authenticationCallback)
        } else if(promptData.fragmentActivity != null){
            BiometricPrompt(promptData.fragmentActivity, promptData.executor, authenticationCallback)
        } else {
            return false
        }

        cancellationSignal = CancellationSignal()
        selfCancelled = false
        return when(val co = this.cryptoObject){
            is CryptoObjectResult.Error -> {
                false
            }
            is CryptoObjectResult.Result -> {
                biometricPrompt.authenticate(promptData.info, co.cryptoObject)
                true
            }
        }

    }

    override fun stopListening() {
        if (cancellationSignal != null) {
            selfCancelled = true
            cancellationSignal?.cancel()
            cancellationSignal = null
        }
    }

    override fun getPublicKey(): PublicKeyResult {
        var publicKey: PublicKey? = null
        return try {
            keyStore.load(null)
            publicKey = keyStore.getCertificate(_keyStoreName).publicKey
            PublicKeyResult.Result(publicKey)
        } catch (e: Exception) {
            PublicKeyResult.Error(e)
        }
    }


    class FingerprintKeyChangedException: Throwable()

    override fun checkSelfPermission(): Boolean {
        return ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED
    }

    override fun resetAll(){
        enableFingerPrint(status = BioAuthSettings.BiometricStatus.Unknown)
    }

    sealed class CryptoObjectResult{
        class Error(val error: Throwable?): CryptoObjectResult()
        class Result(val cryptoObject: BiometricPrompt.CryptoObject): CryptoObjectResult()
    }
    sealed class SignatureResult{
        class Error(val error: Throwable?): SignatureResult()
        class Result(val signature: Signature): SignatureResult()
    }
    sealed class SigningResult{
        object BiometricKeyChanged: SigningResult()
        object Error: SigningResult()
        class Result(val signed: String): SigningResult()
    }
    sealed class PublicKeyResult{
        class Error(val error: Throwable?): PublicKeyResult()
        class Result(val publicKey: PublicKey): PublicKeyResult()
    }
    sealed class PublicKeyPemResult{
        object Error: PublicKeyPemResult()
        class Result(val publicKey: String): PublicKeyPemResult()
    }

    class Builder( private val context: Context, private val settings: BioAuthSettings){
        private var digest  =  KeyProperties.DIGEST_SHA256
        private var algorithm = "SHA256withECDSA"
        private var keyStoreName = "bioauthKey"
        private var ecGenParameterSpec = ECGenParameterSpec("secp256r1")
        fun withDigest(digest: String): Builder{
            this.digest = digest
            return this
        }
        fun withAlgorithm(algorithm: String): Builder{
            this.algorithm = algorithm
            return this
        }
        fun withKeyStoreName(name: String): Builder{
            keyStoreName = name
            return this
        }
        fun withECGenParameterSpec(ecGenParam: ECGenParameterSpec): Builder{
            ecGenParameterSpec = ecGenParam
            return this
        }
        fun build() = BioAuthManager(context, settings).apply {
            this._ecGenParameterSpec = ecGenParameterSpec
            this._digest = digest
            this._alg = algorithm
            this._keyStoreName = keyStoreName
        }
    }

}

private fun PublicKey.toPEM() = "-----BEGIN PUBLIC KEY-----\n${String(this.encoded.encodeBase64(), Charsets.US_ASCII)}\n-----END PUBLIC KEY-----"
private fun ByteArray.encodeBase64(): ByteArray = Base64.encode(this, Base64.DEFAULT)
