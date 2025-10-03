package com.bioauth.sample

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import com.bioauth.lib.manager.authentication.AuthenticationSettings
import com.bioauth.lib.manager.authentication.EncryptedData

class MyPasswordAuthSettings(context: Context): AuthenticationSettings {

    private var prefs: SharedPreferences = context.applicationContext.getSharedPreferences(
            "MyPasswordAuthSettings", Context.MODE_PRIVATE)

    override fun getEnrolmentStatus(): AuthenticationSettings.EnrolmentStatus {
        return when(prefs.getString("PasswordAuthSettings.enabled", null)){
            "true" -> AuthenticationSettings.EnrolmentStatus.Enabled
            "false" -> AuthenticationSettings.EnrolmentStatus.Disabled
            else -> AuthenticationSettings.EnrolmentStatus.Unknown
        }
    }

    override fun setEnrolmentStatus(status: AuthenticationSettings.EnrolmentStatus) {
        val enabled = when(status){
            AuthenticationSettings.EnrolmentStatus.Enabled -> "true"
            AuthenticationSettings.EnrolmentStatus.Disabled -> "false"
            AuthenticationSettings.EnrolmentStatus.Unknown -> "-"
        }
        prefs.edit().putString("PasswordAuthSettings.enabled", enabled).apply()
    }

    // Add this constant with the others
    private companion object {
        const val ENCRYPTED_KEY_PREF = "encrypted_private_key"
        const val ENCRYPTED_IV_PREF = "encrypted_private_key_iv"
        const val ENCRYPTED_SALT_PREF = "encrypted_private_key_salt"
        const val PUBLIC_KEY_PREF = "public_key"
    }


    override fun storePublicKey(publicKeyBytes: ByteArray) {
        val editor = prefs.edit()
        editor.putString(PUBLIC_KEY_PREF, Base64.encodeToString(publicKeyBytes, Base64.DEFAULT))
        editor.apply()
    }

    override fun getPublicKey(): ByteArray? {
        val publicKeyString = prefs.getString(PUBLIC_KEY_PREF, null)
        return if (publicKeyString != null) {
            Base64.decode(publicKeyString, Base64.DEFAULT)
        } else {
            null
        }
    }

    override fun clearPublicKey() {
        val editor = prefs.edit()
        editor.remove(PUBLIC_KEY_PREF)
        editor.apply()
    }
    override fun storePublicKeyId(publicKeyId: String) {
        //OK, we can store this in our local db
    }

    override fun getPublicKeyId(): String? {
        //Retrieve from DB and return it. For this case, just hardcoded
        return "1"
    }


    override fun storeEncryptedPrivateKey(encryptedData: EncryptedData) {
        val editor = prefs.edit()
        editor.putString(ENCRYPTED_KEY_PREF, Base64.encodeToString(encryptedData.encryptedKey, Base64.DEFAULT))
        editor.putString(ENCRYPTED_IV_PREF, Base64.encodeToString(encryptedData.iv, Base64.DEFAULT))
        editor.putString(ENCRYPTED_SALT_PREF, Base64.encodeToString(encryptedData.salt, Base64.DEFAULT))
        editor.apply()
    }

    override fun getEncryptedPrivateKey(): EncryptedData? {
        val encryptedKeyString = prefs.getString(ENCRYPTED_KEY_PREF, null)
        val ivString = prefs.getString(ENCRYPTED_IV_PREF, null)
        val saltString = prefs.getString(ENCRYPTED_SALT_PREF, null)

        return if (encryptedKeyString != null && ivString != null && saltString != null) {
            EncryptedData(
                encryptedKey = Base64.decode(encryptedKeyString, Base64.DEFAULT),
                iv = Base64.decode(ivString, Base64.DEFAULT),
                salt = Base64.decode(saltString, Base64.DEFAULT)
            )
        } else {
            null
        }
    }

    override fun clearEncryptedPrivateKey() {
        val editor = prefs.edit()
        editor.remove(ENCRYPTED_KEY_PREF)
        editor.remove(ENCRYPTED_IV_PREF)
        editor.remove(ENCRYPTED_SALT_PREF)
        editor.apply()
    }
}