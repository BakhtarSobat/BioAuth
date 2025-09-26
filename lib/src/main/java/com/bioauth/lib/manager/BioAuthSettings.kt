package com.bioauth.lib.manager

interface BioAuthSettings {
    sealed class BiometricStatus{
        data object Enabled: BiometricStatus()
        data object Disabled: BiometricStatus()
        data object Unknown: BiometricStatus()
    }
    fun isEnabled(): BiometricStatus
    fun setBiometricStatus(status: BiometricStatus)
    fun storePublicKeyId(publicKeyId: String)
    fun getPublicKeyId(): String?
}