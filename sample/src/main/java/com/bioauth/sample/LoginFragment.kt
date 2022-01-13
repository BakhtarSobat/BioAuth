package com.bioauth.sample

import android.os.Bundle
import android.os.Handler
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.bioauth.lib.jwt.JwtObject
import com.bioauth.lib.manager.BioAuthManager
import com.bioauth.lib.manager.BioAuthSettings
import com.bioauth.lib.manager.IBioAuthManager.AuthenticationTypes.SUCCESS
import com.bioauth.sample.server.MyServer
import java.util.*
import java.util.concurrent.Executor

private const val SALT = "SUPER_SALT"
class LoginFragment: Fragment() {
    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo



    private val myServer by lazy { MyServer(requireContext()) }
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
        fingerprintIcon.setOnClickListener {
            setupFingerprint()
        }
        setIcon()
        return v
    }

    private fun setIcon(){
        fingerprintIcon.visibility = when(bioAuthManager.getBiometricsState(BiometricManager.Authenticators.BIOMETRIC_STRONG)){
            SUCCESS -> View.VISIBLE
            else ->View.INVISIBLE
        }
    }

    private fun setupFingerprint() {
        showFingerprintDialog()
    }

    private fun showFingerprintDialog() {
        executor = ContextCompat.getMainExecutor(requireContext())
        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int,
                                                   errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Toast.makeText(requireContext(),
                        "Authentication error: $errString", Toast.LENGTH_SHORT)
                        .show()
                }

                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    Toast.makeText(requireContext(),
                        "Authentication succeeded!", Toast.LENGTH_SHORT)
                        .show()
                    checkingFingerprint()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(requireContext(), "Authentication failed",
                        Toast.LENGTH_SHORT)
                        .show()
                }
            })

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric login for my app")
            .setSubtitle("Log in using your biometric credential")
            .setNegativeButtonText("Use account password")
            .build()

        // Prompt appears when user clicks "Log in".
        // Consider integrating with the keystore to unlock cryptographic operations,
        // if needed by your app.
        biometricPrompt.authenticate(promptInfo)
    }

    private fun checkingFingerprint() {
        fingerprintLabel.text = "Authentication with the server..."
        fingerprintIcon.setImageResource(R.drawable.ic_check)
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
                    fingerprintIcon.setImageResource(R.drawable.ic_error)
                    Toast.makeText(activity, "Unable to verify challenge", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun checkingFingerprintJWT() {
        fingerprintLabel?.text = "Authentication with the server..."
        fingerprintIcon.setImageResource(R.drawable.ic_check)
        val challenge = myServer.getChallenge()
        val jwt = JwtObject.createForEC256().apply {
            addClaim("jti", challenge)
        }
        val response = bioAuthManager.signChallenge(jwt)
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
                val verified: Boolean  = myServer.verifyJwt(response.signed)
                if(verified){
                    Handler().postDelayed({listener?.loggedIn()}, 500)
                } else {
                    fingerprintIcon.setImageResource(R.drawable.ic_error)
                    Toast.makeText(activity, "Unable to verify challenge", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun createBioAuthManager(): BioAuthManager {
        return BioAuthManager.Builder(requireContext(), MyBioAuthSettings(requireContext())).build()
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