package com.bioauth.sample

import android.support.v7.app.AppCompatActivity
import android.os.Bundle
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
