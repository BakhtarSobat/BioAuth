package com.bioauth.lib.manager.authentication.biometrics.builder

import android.content.Context
import com.bioauth.lib.manager.authentication.AuthenticationSettings
import com.bioauth.lib.manager.authentication.biometrics.BiometricAuthenticationManager
import com.bioauth.lib.manager.authentication.biometrics.BiometricAuthenticationManagerImpl
import com.bioauth.lib.manager.authentication.biometrics.BiometricAuthenticationManagerImpl.Config
import java.security.spec.ECGenParameterSpec

// DSL marker for type safety
@DslMarker
annotation class BiometricAuthDsl

// Configuration class as receiver for the DSL
@BiometricAuthDsl
class BiometricAuthConfig {
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

// Standalone function for creating the manager with DSL
fun biometricAuthenticationManager(
    context: Context,
    settings: AuthenticationSettings,
    init: BiometricAuthConfig.() -> Unit = {}
): BiometricAuthenticationManager {
    val config = BiometricAuthConfig().apply(init)
    return BiometricAuthenticationManagerImpl(context, settings, config.toConfig())
}