package com.bioauth.lib.manager.authentication

class EncryptedData(
    val encryptedKey: ByteArray,
    val iv: ByteArray,
    val salt: ByteArray
)