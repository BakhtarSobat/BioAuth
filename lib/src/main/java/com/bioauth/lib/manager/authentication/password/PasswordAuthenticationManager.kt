package com.bioauth.lib.manager.authentication.password

import android.util.Base64
import android.util.Log
import com.bioauth.lib.manager.authentication.AuthenticationSettings
import com.bioauth.lib.manager.authentication.EncryptedData
import com.bioauth.lib.manager.authentication.SignableObject
import com.bioauth.lib.manager.authentication.biometrics.BiometricAuthenticationManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

interface PasswordAuthenticationManager {
    sealed class SigningResult {
        data class Success(val signature: String) : SigningResult()
        data class Error(val message: String) : SigningResult()
        data object PasswordChanged : SigningResult()
    }

    suspend fun getPasswordEnrolmentStatus(): AuthenticationSettings.EnrolmentStatus
    fun setPasswordEnrolmentStatus(status: AuthenticationSettings.EnrolmentStatus)
    suspend fun enroll(password: String): Result<String>
    suspend fun getPublicKey(): Result<PublicKey>
    fun resetAll()
    suspend fun signWithPassword(
        challenge: SignableObject,
        password: String
    ): SigningResult
}

data class Config(
    val digest: String = "SHA256",
    val algorithm: String = "SHA256withECDSA",
    val keyStoreName: String = "passwordAuthKey",
    val ecGenParameterSpec: ECGenParameterSpec = ECGenParameterSpec("secp256r1")
)

internal class PasswordAuthenticationManagerImpl(
    private val settings: AuthenticationSettings,
    private val config: Config,
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
) : PasswordAuthenticationManager {

    private val keyGenerator by lazy {
        KeyPairGenerator.getInstance("EC") // Software-based EC key generation
    }
    private fun deriveKeyFromPassword(password: String, salt: ByteArray): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password.toCharArray(), salt, 100000, 256)
        return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
    }

    private fun encryptPrivateKey(privateKey: PrivateKey, password: String): EncryptedData {
        val salt = SecureRandom().generateSeed(16)
        val derivedKey = deriveKeyFromPassword(password, salt)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, derivedKey)

        val encryptedKey = cipher.doFinal(privateKey.encoded)
        return EncryptedData(encryptedKey, cipher.iv, salt)
    }

    private fun decryptPrivateKey(encryptedData: EncryptedData, password: String): PrivateKey {
        val derivedKey = deriveKeyFromPassword(password, encryptedData.salt)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, encryptedData.iv)
        cipher.init(Cipher.DECRYPT_MODE, derivedKey, gcmSpec)

        val decryptedKeyBytes = cipher.doFinal(encryptedData.encryptedKey)
        val keySpec = PKCS8EncodedKeySpec(decryptedKeyBytes)

        return KeyFactory.getInstance("EC").generatePrivate(keySpec)
    }

    private suspend fun createKeyPair(): Result<KeyPair> = withContext(Dispatchers.IO) {
        runCatching {
            keyGenerator.initialize(ECGenParameterSpec("secp256r1"))
            keyGenerator.generateKeyPair()
        }
    }

    private suspend fun storeEncryptedPrivateKey(keyPair: KeyPair, password: String): Result<Unit> =
        withContext(Dispatchers.IO) {
            runCatching {
                val encryptedData = encryptPrivateKey(keyPair.private, password)
                settings.storeEncryptedPrivateKey(encryptedData)
                settings.storePublicKey(keyPair.public.encoded)
            }
        }

    override suspend fun enroll(password: String): Result<String> = withContext(Dispatchers.IO) {
        createKeyPair().fold(
            onSuccess = { keyPair ->
                storeEncryptedPrivateKey(keyPair, password).fold(
                    onSuccess = {
                        settings.setEnrolmentStatus(AuthenticationSettings.EnrolmentStatus.Enabled)
                        settings.storePublicKeyId(config.keyStoreName)
                        Result.success(keyPair.public.toPEM())
                    },
                    onFailure = {
                        Log.e("Auth", it.message, it)
                        Result.failure(it)
                    }
                )
            },
            onFailure = { Result.failure(it) }
        )
    }

    private fun initSignatureWithPassword(password: String): Result<Signature> {
        return runCatching {
            val encryptedKeyData = settings.getEncryptedPrivateKey()
                ?: throw IllegalStateException("No encrypted private key found")

            val privateKey = decryptPrivateKey(encryptedKeyData, password)

            val signature = Signature.getInstance(config.algorithm)
            signature.initSign(privateKey)
            signature
        }
    }

    override suspend fun signWithPassword(
        challenge: SignableObject,
        password: String
    ): PasswordAuthenticationManager.SigningResult = withContext(Dispatchers.IO) {
        return@withContext initSignatureWithPassword(password).fold(
            onSuccess = { signature ->
                when (val signingResult = challenge.sign(signature)) {
                    is BiometricAuthenticationManager.SigningResult.Success -> {
                        PasswordAuthenticationManager.SigningResult.Success(signingResult.signature)
                    }

                    is BiometricAuthenticationManager.SigningResult.BiometricKeyChanged -> {
                        setPasswordEnrolmentStatus(AuthenticationSettings.EnrolmentStatus.Disabled)
                        PasswordAuthenticationManager.SigningResult.PasswordChanged
                    }

                    is BiometricAuthenticationManager.SigningResult.Error -> {
                        PasswordAuthenticationManager.SigningResult.Error(signingResult.message)
                    }
                }
            },
            onFailure = { error ->
                if (error is BadPaddingException) {
                    PasswordAuthenticationManager.SigningResult.Error("Invalid password")
                } else {
                    PasswordAuthenticationManager.SigningResult.Error(error.message ?: "Signing failed")
                }
            }
        )
    }

    override suspend fun getPublicKey(): Result<PublicKey> = withContext(Dispatchers.IO) {
        runCatching {
            val publicKeyBytes = settings.getPublicKey()
                ?: throw IllegalStateException("No public key found")

            val keySpec = X509EncodedKeySpec(publicKeyBytes)
            KeyFactory.getInstance("EC").generatePublic(keySpec)
        }
    }

    override suspend fun getPasswordEnrolmentStatus(): AuthenticationSettings.EnrolmentStatus =
        withContext(Dispatchers.IO) {
            val enabled = settings.getEnrolmentStatus()
            val publicKeyId = settings.getPublicKeyId()

            if (enabled == AuthenticationSettings.EnrolmentStatus.Enabled && !publicKeyId.isNullOrEmpty()) {
                AuthenticationSettings.EnrolmentStatus.Enabled
            } else {
                enabled
            }
        }

    override fun setPasswordEnrolmentStatus(status: AuthenticationSettings.EnrolmentStatus) {
        scope.launch {
            settings.setEnrolmentStatus(status)
        }
    }

    override fun resetAll() {
        runBlocking {
            setPasswordEnrolmentStatus(AuthenticationSettings.EnrolmentStatus.Unknown)
            settings.clearEncryptedPrivateKey()
            settings.clearPublicKey()
        }
    }


}

private fun PublicKey.toPEM(): String {
    val encodedKey = Base64.encodeToString(encoded, Base64.DEFAULT)
    return "-----BEGIN PUBLIC KEY-----\n$encodedKey-----END PUBLIC KEY-----"
}

