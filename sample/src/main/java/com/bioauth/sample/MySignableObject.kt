package com.bioauth.sample

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.util.Base64
import com.bioauth.lib.manager.BioAuthManager
import com.bioauth.lib.manager.SignableObject
import java.security.KeyStoreException
import java.security.Signature
import java.security.SignatureException

/**
 * This can be Jwt or any other string the can be signed
 */
class MySignableObject(val challenge: String): SignableObject {
    override fun sign(signature: Signature): BioAuthManager.SigningResult {
        return try {
            signature.update(challenge.toByteArray(Charsets.UTF_8))
            val signatureBytes = signature.sign()
            val signed = Base64.encodeToString(signatureBytes, Base64.URL_SAFE or Base64.NO_WRAP)
            BioAuthManager.SigningResult.Result(signed)
        } catch (e: KeyPermanentlyInvalidatedException){
            BioAuthManager.SigningResult.BiometricKeyChanged
        } catch (e: KeyStoreException){
            BioAuthManager.SigningResult.BiometricKeyChanged
        } catch (e: SignatureException){
            BioAuthManager.SigningResult.BiometricKeyChanged
        }
    }
}