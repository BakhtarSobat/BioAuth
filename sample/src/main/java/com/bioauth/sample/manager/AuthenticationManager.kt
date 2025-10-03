package com.bioauth.sample.manager

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow

object AuthenticationManager {
    sealed interface AuthenticationState {
        object Idle : AuthenticationState
        object Loading : AuthenticationState
        data class Success(val message: String) : AuthenticationState
        data class Error(val error: String) : AuthenticationState
    }

    private val _authenticationStateFlow: MutableStateFlow<AuthenticationState> =
        MutableStateFlow(AuthenticationState.Idle)
    val authenticationStateFlow: Flow<AuthenticationState> = _authenticationStateFlow

    fun resetState() {
        _authenticationStateFlow.value = AuthenticationState.Idle
    }

    fun setLoading() {
        _authenticationStateFlow.value = AuthenticationState.Loading
    }

    fun setSuccess(message: String) {
        _authenticationStateFlow.value = AuthenticationState.Success(message)
    }

    fun setError(error: String) {
        _authenticationStateFlow.value = AuthenticationState.Error(error)
    }
}