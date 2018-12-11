package com.bioauth.sample

import com.bioauth.lib.manager.SignableObject

/**
 * This can be Jwt or any other string the can be signed
 */
class MySignableObject(val serverChallenge: String): SignableObject() {
    override fun getChallenge() = serverChallenge
}