package com.bioauth.lib.manager.authentication.password.builder

import com.bioauth.lib.manager.authentication.AuthenticationSettings
import com.bioauth.lib.manager.authentication.password.Config
import com.bioauth.lib.manager.authentication.password.PasswordAuthenticationManager
import com.bioauth.lib.manager.authentication.password.PasswordAuthenticationManagerImpl
import java.security.spec.ECGenParameterSpec

// DSL marker to improve type safety in the DSL scope
@DslMarker
annotation class PasswordAuthDsl

// Configuration class that acts as a receiver for the DSL
@PasswordAuthDsl
class PasswordAuthConfig {
    var digest: String? = null
    var algorithm: String? = null
    var keyStoreName: String? = null
    var ecGenParameterSpec: ECGenParameterSpec? = null

    internal fun toConfig(): Config {
        val baseConfig = Config()
        return baseConfig.copy(
            digest = digest ?: baseConfig.digest,
            algorithm = algorithm ?: baseConfig.algorithm,
            keyStoreName = keyStoreName ?: baseConfig.keyStoreName,
            ecGenParameterSpec = ecGenParameterSpec ?: baseConfig.ecGenParameterSpec
        )
    }
}

fun passwordAuthenticationManager(settings: AuthenticationSettings, init: PasswordAuthConfig.() -> Unit = {}): PasswordAuthenticationManager {
    val config = PasswordAuthConfig().apply(init)
    return PasswordAuthenticationManagerImpl(settings, config.toConfig())
}