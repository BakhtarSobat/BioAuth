package com.bioauth.sample

import android.content.Context
import android.content.SharedPreferences
import com.bioauth.lib.manager.authentication.AuthenticationSettings
import com.bioauth.lib.manager.authentication.EncryptedData


class MyBioAuthSettings(context: Context): AuthenticationSettings {

    private var prefs: SharedPreferences = context.applicationContext.getSharedPreferences(
            "MyBioAuthSettings", Context.MODE_PRIVATE)

    override fun getEnrolmentStatus(): AuthenticationSettings.EnrolmentStatus {
        return when(prefs.getString("BioAuthSettings.enabled", null)){
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
        prefs.edit().putString("BioAuthSettings.enabled", enabled).apply()
    }

    override fun storePublicKeyId(publicKeyId: String) {
        //OK, we can store this in our local db
    }

    override fun getPublicKeyId(): String? {
        //Retrieve from DB and return it. For this case, just hardcoded
        return "1"
    }

    override fun storeEncryptedPrivateKey(encryptedData: EncryptedData) {
        TODO("Not yet implemented")
    }

    override fun getEncryptedPrivateKey(): EncryptedData? {
        TODO("Not yet implemented")
    }

    override fun clearEncryptedPrivateKey() {
        TODO("Not yet implemented")
    }

    override fun storePublicKey(publicKeyBytes: ByteArray) {
        TODO("Not yet implemented")
    }

    override fun getPublicKey(): ByteArray? {
        TODO("Not yet implemented")
    }

    override fun clearPublicKey() {
        TODO("Not yet implemented")
    }
}