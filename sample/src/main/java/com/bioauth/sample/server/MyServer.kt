package com.bioauth.sample.server

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.util.Base64
import android.util.Log
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.*

private const val SALT = "SUPER_SALT"
private const val CURVE_ALG = "SHA256withECDSA"

class MyServer(context: Context) {
    private val serverChallenge by lazy { UUID.randomUUID().toString() }
    private var prefs: SharedPreferences = context.applicationContext.getSharedPreferences(
            "MyServer", Context.MODE_PRIVATE)
    fun loginWithPin(pin: String) = "1234" == pin

    fun enrollFingerprint(device: String, publicKey: String) {
        prefs.edit().putString("publicKey", publicKey).apply()
        Log.d("PublicKey", publicKey)
    }

    fun getChallenge() = serverChallenge

    fun verify(response: String, nonce: Int): Boolean {
        val publicKey = loadPublicKey()
        val data = "$serverChallenge$SALT$nonce"
        if(publicKey != null){
            val verificationFunction = Signature.getInstance("SHA256withECDSA")
            verificationFunction.initVerify(publicKey)
            verificationFunction.update(data.toByteArray())
            val respByte =  Base64.decode(response, Base64.NO_WRAP or Base64.URL_SAFE)
            return verificationFunction.verify(respByte)
        } else {
            return false
        }
    }

    private fun loadPublicKey(): PublicKey?{
        var pk: String? = prefs.getString("publicKey", null)
        pk = pk?.replace("-----BEGIN PUBLIC KEY-----\n", "")
        pk = pk?.replace("-----END PUBLIC KEY-----", "")
        pk = pk?.replace("\n", "")
        return if(pk != null){
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val pkb = java.util.Base64.getDecoder().decode(pk)
                getPublicKey(pkb)
            } else {
                null
            }
        } else {
            null
        }
    }

    private fun getPublicKey(pkb: ByteArray?): PublicKey? {
        return if(pkb != null) {
            val fact = KeyFactory.getInstance("EC")
            fact.generatePublic(X509EncodedKeySpec(pkb))
        } else {
            null
        }
    }

    fun verifyJwt(signed: String): Boolean {
        return true//No implementation
    }
}