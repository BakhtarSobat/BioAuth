package com.bioauth.sample

import android.os.Bundle
import android.os.Handler
import android.support.v4.app.Fragment
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import com.bioauth.lib.manager.BioAuthManager
import com.bioauth.lib.manager.BioAuthSettings
import com.bioauth.sample.server.MyServer
import java.util.*

private const val SALT = "SUPER_SALT"
class LoginFragment: Fragment() {
    private val myServer by lazy { MyServer(context!!) }
    private val bioAuthManager: BioAuthManager by lazy{createBioAuthManager()}
    private var listener: Listener? = null
    private lateinit var fingerprintIcon: ImageView
    private lateinit var fingerprintLabel: TextView

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        val v = inflater.inflate(R.layout.frag_login, null, false)
        v.findViewById<Button>(R.id.login_button).setOnClickListener {
            val pin = v.findViewById<TextView>(R.id.login_pin).text.toString()
            handleLogin(pin)
        }
        fingerprintIcon = v.findViewById<ImageView>(R.id.login_fingerprint)
        fingerprintLabel = v.findViewById<TextView>(R.id.login_fingerprint_label)
        Handler().postDelayed({setupFingerprint()}, 500)
        return v
    }

    private fun setupFingerprint() {
        if (bioAuthManager.isFingerprintAuthAvailable() && bioAuthManager.isFingerEnabled() == BioAuthSettings.BiometricStatus.Enabled) {
            fingerprintIcon?.visibility = View.VISIBLE
            bioAuthManager.startListening(object : FingerprintManagerCompat.AuthenticationCallback() {
                override fun onAuthenticationError(errMsgId: Int, errString: CharSequence) {
                    fingerprintIcon?.setImageResource(R.drawable.ic_error)
                    Toast.makeText(activity, errString, Toast.LENGTH_LONG).show()
                }

                override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence) {

                }

                override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult) {
                    checkingFingerprint()
                }

                override fun onAuthenticationFailed() {
                    fingerprintIcon?.setImageResource(R.drawable.ic_error)
                    Toast.makeText(activity, "Fingerprint Authentication failed", Toast.LENGTH_LONG).show()

                }
            })
        } else {
            fingerprintIcon?.visibility = View.GONE
        }
    }

    private fun checkingFingerprint() {
        fingerprintLabel?.text = "Authentication with the server..."
        fingerprintIcon?.setImageResource(R.drawable.ic_check)
        val challenge = myServer.getChallenge()
        val nonce = Random().nextInt(100)
        val stringToSign = "$challenge$SALT$nonce"
        val response = bioAuthManager.signChallenge(MySignableObject(stringToSign))
        when(response){

            BioAuthManager.SigningResult.BiometricKeyChanged -> {
                Toast.makeText(activity, "Fingerprint changed, please enroll again", Toast.LENGTH_LONG).show()
                bioAuthManager.enableFingerPrint(BioAuthSettings.BiometricStatus.Unknown)
            }
            BioAuthManager.SigningResult.Error -> {
                Toast.makeText(activity, "Error while creating response, please enroll again", Toast.LENGTH_LONG).show()
                bioAuthManager.enableFingerPrint(BioAuthSettings.BiometricStatus.Unknown)
            }
            is BioAuthManager.SigningResult.Result -> {
                val verified: Boolean  = myServer.verify(response.signed, nonce)
                if(verified){
                    Handler().postDelayed({listener?.loggedIn()}, 500)
                } else {
                    fingerprintIcon?.setImageResource(R.drawable.ic_error)
                    Toast.makeText(activity, "Unable to verify challenge", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun createBioAuthManager(): BioAuthManager {
        return BioAuthManager.Builder(context!!, MyBioAuthSettings(context!!)).build()
    }

    private fun handleLogin(pin: String) {
        if(myServer.loginWithPin(pin)){
            listener?.loggedIn()
        }
    }

    override fun onPause() {
        super.onPause()
        bioAuthManager.stopListening()

    }

    interface Listener{
        fun loggedIn()
    }


    companion object {
        fun createFragment(listener: LoginFragment.Listener) = LoginFragment().apply {
            this.listener = listener
        }
    }
}