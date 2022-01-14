package com.bioauth.sample

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import androidx.biometric.BiometricManager
import com.bioauth.lib.manager.BioAuthSettings
import com.bioauth.lib.manager.IBioAuthManager
import com.bioauth.sample.server.MyServer
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        gotoLoginFragment()

    }

    private fun gotoLoginFragment() {
        val fragment = LoginFragment.createFragment(object : LoginFragment.Listener {
            override fun loggedIn() {
                gotoLoggedFragment()
            }

        })
        supportFragmentManager.beginTransaction().replace(R.id.fragment, fragment).commit()
    }
    private fun gotoLoggedFragment() {
        val fragment = LoggedInFragment.createFragment(object : LoggedInFragment.Listener {
            override fun loggedOut() {
                gotoLoginFragment()
            }

        })
        supportFragmentManager.beginTransaction().replace(R.id.fragment, fragment).commit()
    }
}

fun IBioAuthManager.getAuthenticator() = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.BIOMETRIC_WEAK
fun IBioAuthManager.getBiometricsState() = this.getBiometricsState(getAuthenticator())


fun IBioAuthManager.isFingerprintEnrolled() = this.getBiometricsState() == IBioAuthManager.AuthenticationTypes.SUCCESS
fun IBioAuthManager.isFingerprintReadyToUse() = this.isFingerprintEnrolled() && this.isFingerEnabled() == BioAuthSettings.BiometricStatus.Enabled
