package com.bioauth.sample

import android.content.Context
import com.bioauth.lib.manager.BioAuthSettings
import android.content.SharedPreferences



class MyBioAuthSettings(context: Context): BioAuthSettings {

    private var prefs: SharedPreferences = context.applicationContext.getSharedPreferences(
            "MyBioAuthSettings", Context.MODE_PRIVATE)

    override fun isEnabled(): BioAuthSettings.BiometricStatus {
        return when(prefs.getString("BioAuthSettings.enabled", null)){
            "true" -> BioAuthSettings.BiometricStatus.Enabled
            "false" -> BioAuthSettings.BiometricStatus.Disabled
            else -> BioAuthSettings.BiometricStatus.Unknown
        }
    }

    override fun setBiometricStatus(status: BioAuthSettings.BiometricStatus) {
        val enabled = when(status){

            BioAuthSettings.BiometricStatus.Enabled -> "true"
            BioAuthSettings.BiometricStatus.Disabled -> "false"
            BioAuthSettings.BiometricStatus.Unknown -> "-"
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
}