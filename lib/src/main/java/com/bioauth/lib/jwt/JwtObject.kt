package com.bioauth.lib.jwt
import android.os.Build
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.support.annotation.RequiresApi
import android.util.Base64
import com.bioauth.lib.manager.BioAuthManager
import com.bioauth.lib.manager.SignableObject
import com.google.gson.GsonBuilder
import java.security.KeyStoreException
import java.security.Signature
import java.security.SignatureException


class JwtObject: SignableObject() {
    override fun getChallenge(): String {
        val header = headerEncoded()
        val body = bodyEncoded()
        val toSign  = "$header.$body"
        return toSign
    }


    private val header = HashMap<String, String>()
    private val body = HashMap<String, String>()
    private val gson by lazy { GsonBuilder().disableHtmlEscaping().create() }

    companion object {
        fun createForEC521() = JwtObject().apply {
            header["alg"] = "ES512"
            header["typ"] = "JWT"

        }

        fun createForEC256() = JwtObject().apply {
            header["alg"] = "ES256"
            header["typ"] = "JWT"
        }
    }

    private fun headerJson(): String = gson.toJson(header)
    private fun bodyJson(): String = gson.toJson(body)
    private fun headerEncoded()= headerJson().toByteArray(Charsets.UTF_8).base64UrlEncode()
    private fun bodyEncoded()  =  bodyJson().toByteArray(Charsets.UTF_8).base64UrlEncode()

    fun addClaim(key: String, value: String){
        body[key] = value
    }

    fun addHeader(key: String, value: String){
        header[key] = value
    }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun sign(signature: Signature): BioAuthManager.SigningResult {
        val toSign  = getChallenge()
        return try {
            signature.update(toSign.toByteArray(Charsets.UTF_8))
            val signatureBytes = signature.sign()
            val rsByteArrayLength = ECDSA.getSignatureByteArrayLength(this.header["alg"])
            val jwsSignature = ECDSA.transcodeSignatureToConcat(signatureBytes, rsByteArrayLength)
            val jwsSignedStr = jwsSignature.base64UrlEncode()
            BioAuthManager.SigningResult.Result("$toSign.$jwsSignedStr")
        } catch (e: KeyPermanentlyInvalidatedException){
            BioAuthManager.SigningResult.BiometricKeyChanged
        } catch (e: KeyStoreException){
            BioAuthManager.SigningResult.BiometricKeyChanged
        } catch (e: SignatureException){
            BioAuthManager.SigningResult.BiometricKeyChanged
        }
    }

    private fun ByteArray.base64UrlEncode(): String = Base64.encodeToString(this,Base64.URL_SAFE or Base64.NO_WRAP)

}