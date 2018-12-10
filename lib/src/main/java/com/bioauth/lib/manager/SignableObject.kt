package com.bioauth.lib.manager

import java.security.Signature

interface SignableObject {
    fun sign(signature: Signature): BioAuthManager.SigningResult
}