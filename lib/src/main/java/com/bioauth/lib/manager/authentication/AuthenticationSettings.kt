package com.bioauth.lib.manager.authentication

interface AuthenticationSettings {
    sealed class EnrolmentStatus{
        data object Enabled: EnrolmentStatus()
        data object Disabled: EnrolmentStatus()
        data object Unknown: EnrolmentStatus()
    }


    fun getEnrolmentStatus(): EnrolmentStatus
    fun setEnrolmentStatus(status: EnrolmentStatus)
    fun storePublicKeyId(publicKeyId: String)
    fun getPublicKeyId(): String?

    fun storeEncryptedPrivateKey(encryptedData: EncryptedData)
    fun getEncryptedPrivateKey(): EncryptedData?
    fun clearEncryptedPrivateKey()

    fun storePublicKey(publicKeyBytes: ByteArray)
    fun getPublicKey(): ByteArray?
    fun clearPublicKey()
}