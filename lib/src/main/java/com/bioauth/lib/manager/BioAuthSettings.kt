package com.bioauth.lib.manager

interface BioAuthSettings {
    sealed class BiometricStatus{
        object Enabled: BiometricStatus()
        object Disabled: BiometricStatus()
        object Unknown: BiometricStatus()
    }
    fun isEnabled(): BiometricStatus
    fun setBiometricStatus(status: BiometricStatus)
    fun storePublicKeyId(publicKeyId: String)
    fun getPublicKeyId(): String?
}