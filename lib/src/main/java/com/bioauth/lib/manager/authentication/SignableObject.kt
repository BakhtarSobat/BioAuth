package com.bioauth.lib.manager.authentication

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.util.Base64
import android.util.Log
import com.bioauth.lib.manager.authentication.biometrics.BiometricAuthenticationManager
import java.security.KeyStoreException
import java.security.Signature
import java.security.SignatureException

abstract class SignableObject {
    abstract fun getChallenge(): String

    open fun sign(signature: Signature): BiometricAuthenticationManager.SigningResult {
        return try {
            signature.update(getChallenge().toByteArray(Charsets.UTF_8))
            val signatureBytes = signature.sign()
            val signed = Base64.encodeToString(signatureBytes, Base64.URL_SAFE or Base64.NO_WRAP)
            BiometricAuthenticationManager.SigningResult.Success(signed)
        } catch (e: KeyPermanentlyInvalidatedException) {
            BiometricAuthenticationManager.SigningResult.BiometricKeyChanged
        } catch (e: KeyStoreException) {
            BiometricAuthenticationManager.SigningResult.BiometricKeyChanged
        } catch (e: SignatureException) {
            Log.e("SignableObject", "Signature error: ${e.message}", e)
            BiometricAuthenticationManager.SigningResult.Error(e.message ?: "Unknown signature error")
        } catch (e: Exception) {
            Log.e("SignableObject", "Unexpected error: ${e.message}", e)
            BiometricAuthenticationManager.SigningResult.Error(e.message ?: "Unknown error")
        }
    }
}