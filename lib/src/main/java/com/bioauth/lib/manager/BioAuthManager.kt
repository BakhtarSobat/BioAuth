package com.bioauth.lib.manager

import android.Manifest
import android.annotation.TargetApi
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.annotation.RequiresApi
import android.support.v4.app.ActivityCompat
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v4.os.CancellationSignal
import android.util.Base64
import java.security.*
import java.security.spec.ECGenParameterSpec


private const val ANDROID_KEY_STORE = "AndroidKeyStore"

interface IBioAuthManager {
    @RequiresApi(Build.VERSION_CODES.M)
    fun isHardwareDetected(): Boolean

    @RequiresApi(Build.VERSION_CODES.M)
    fun hasEnrolledFingerprints(): Boolean

    fun isFingerprintAuthAvailable(): Boolean
    fun isFingerEnabled(): BioAuthSettings.BiometricStatus
    fun enableFingerPrint(status: BioAuthSettings.BiometricStatus)
    fun savePublicKeyId(publicKeyId: String)
    fun getPublicKeyId(): String?
    @RequiresApi(Build.VERSION_CODES.M)
    fun enroll(): BioAuthManager.PublicKeyPemResult

    @RequiresApi(Build.VERSION_CODES.M)
    fun signChallenge(challenge: SignableObject): BioAuthManager.SigningResult

    fun startListening(callBack: FingerprintManagerCompat.AuthenticationCallback)
    fun stopListening()
    fun getPublicKey(): BioAuthManager.PublicKeyResult
    fun isSupportedSDK(): Boolean
    fun checkSelfPermission(): Boolean
    fun resetAll()
}

class BioAuthManager private constructor(private val context: Context, private val settings: BioAuthSettings) : IBioAuthManager {
    private lateinit var _ecGenParameterSpec: ECGenParameterSpec
    private lateinit var _digest: String
    private lateinit var _alg: String
    private lateinit var _keyStoreName: String

    private val keyGenerator by lazy { KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")}

    private val fingerprintManager by lazy { FingerprintManagerCompat.from(context) }
    private val keyStore: KeyStore by lazy { KeyStore.getInstance(ANDROID_KEY_STORE) }
    private var cancellationSignal: CancellationSignal? = null
    private var selfCancelled: Boolean = false

    private val cryptoObject  by lazy { initCryptoObject() }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun isHardwareDetected(): Boolean {
        return fingerprintManager.isHardwareDetected
    }
    @RequiresApi(Build.VERSION_CODES.M)
    override fun hasEnrolledFingerprints(): Boolean {
        return fingerprintManager.hasEnrolledFingerprints()
    }


    override fun isFingerprintAuthAvailable(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            isHardwareDetected() && hasEnrolledFingerprints()
        } else {
            return false
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
    @TargetApi(Build.VERSION_CODES.M)
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
                            .build())
            keyGenerator.generateKeyPair()
            return true
        } catch (e: InvalidAlgorithmParameterException) {
            return false
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun enroll(): PublicKeyPemResult{
        return try {
            createKeyPair()
            val publicKey = getPublicKey()
            when(publicKey){

                is BioAuthManager.PublicKeyResult.Error -> PublicKeyPemResult.Error
                is BioAuthManager.PublicKeyResult.Result -> PublicKeyPemResult.Result(publicKey.publicKey.toPEM())
            }
        } catch (e: InvalidKeyException) {
            PublicKeyPemResult.Error
        }
    }

    private fun initCryptoObject(): CryptoObjectResult{
        val signatureToSign: SignatureResult = if (isSupportedSDK()) {
            initSignature()
        } else {
            SignatureResult.Error(null)
        }
        return when(signatureToSign){
            is SignatureResult.Result -> {
                val cryptoObject = FingerprintManagerCompat.CryptoObject(signatureToSign.signature)
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

    override fun startListening(callBack: FingerprintManagerCompat.AuthenticationCallback ) {
        if (!isFingerprintAuthAvailable()) {
            return
        }
        cancellationSignal = CancellationSignal()
        selfCancelled = false
        val co = this.cryptoObject
        when(co){
            is BioAuthManager.CryptoObjectResult.Error -> callBack.onAuthenticationError(400, "CryptoObject was not initialized")
            is BioAuthManager.CryptoObjectResult.Result -> fingerprintManager.authenticate(co.cryptoObject, 0, cancellationSignal, callBack, null)
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

    override fun isSupportedSDK(): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
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
        class Result(val cryptoObject: FingerprintManagerCompat.CryptoObject): CryptoObjectResult()
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
