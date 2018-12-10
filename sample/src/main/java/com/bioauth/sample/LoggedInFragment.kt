package com.bioauth.sample

import android.os.Bundle
import android.support.v4.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import com.bioauth.lib.manager.BioAuthManager
import com.bioauth.lib.manager.BioAuthSettings
import com.bioauth.sample.server.MyServer

class LoggedInFragment: Fragment() {
    private var listener: Listener? = null
    private val bioAuthManager by lazy { createBioAuthManager() }
    private val myServer by lazy { MyServer(context!!) }

    private fun createBioAuthManager(): BioAuthManager {
        return BioAuthManager.Builder(context!!, MyBioAuthSettings(context!!)).build()
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        val v = inflater.inflate(R.layout.frag_logged_in, null, false)
        v.findViewById<Button>(R.id.frag_logged_fingerprint).apply {
            setOnClickListener {
                handleEnrollFingerprint()
            }
            this.isEnabled = bioAuthManager.isHardwareDetected() && bioAuthManager.isFingerprintAuthAvailable() && bioAuthManager.hasEnrolledFingerprints() && bioAuthManager.isSupportedSDK()
            val text = if(bioAuthManager.isFingerEnabled() == BioAuthSettings.BiometricStatus.Enabled) "Disable" else "Enroll"
            this.setText(text)

        }
        v.findViewById<Button>(R.id.frag_logged_logout).apply {
            setOnClickListener {
                listener?.loggedOut()
            }
        }

        val text = if(!bioAuthManager.isHardwareDetected()){
            "No Hardware"
        } else if(!bioAuthManager.hasEnrolledFingerprints() ){
            "Please enroll at least one fingerprint"
        } else if(!bioAuthManager.isSupportedSDK()){
            "SDK not supported"
        } else {
            "Welcome"
        }
        v.findViewById<TextView>(R.id.frag_logged_welcome).text = text
        return v
    }

    private fun handleEnrollFingerprint() {
        val result = bioAuthManager.enroll()
        when(result){

            BioAuthManager.PublicKeyPemResult.Error -> {Toast.makeText(context, "Couldn't enroll fingerprint", Toast.LENGTH_LONG).show()}
            is BioAuthManager.PublicKeyPemResult.Result -> {
                sendPublicKey(result.publicKey)
                bioAuthManager.enableFingerPrint(BioAuthSettings.BiometricStatus.Enabled)
            }
        }.let {  }
    }

    private fun sendPublicKey(publicKey: String) {
        myServer.enrollFingerprint("1", publicKey)

    }

    interface Listener {
        fun loggedOut()
    }


    companion object {
        fun createFragment(listener: LoggedInFragment.Listener) = LoggedInFragment().apply {
            this.listener = listener

        }
    }
}