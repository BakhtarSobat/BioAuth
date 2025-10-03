package com.bioauth.sample

import com.bioauth.lib.manager.authentication.SignableObject

/**
 * This can be Jwt or any other string the can be signed
 */
data class MySignableObject(val serverChallenge: String, val nonce: Int): SignableObject() {
    override fun getChallenge() = serverChallenge
}