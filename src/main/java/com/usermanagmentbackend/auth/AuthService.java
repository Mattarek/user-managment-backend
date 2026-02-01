package com.usermanagmentbackend.auth;

import com.usermanagmentbackend.auth.dto.LoginRequest;
import com.usermanagmentbackend.auth.dto.LogoutRequest;
import com.usermanagmentbackend.auth.dto.RefreshTokenRequest;
import com.usermanagmentbackend.auth.dto.RegisterRequest;
import com.usermanagmentbackend.auth.dto.RegisterResponse;
import com.usermanagmentbackend.auth.dto.ResetPasswordRequest;
import com.usermanagmentbackend.auth.dto.TokenPairResponse;

public interface AuthService {
	ResetPasswordRequest resetPassword(ResetPasswordRequest req);

	RegisterResponse register(RegisterRequest req);

	TokenPairResponse login(LoginRequest req);

	TokenPairResponse refresh(RefreshTokenRequest req);

	void logout(LogoutRequest req);
}