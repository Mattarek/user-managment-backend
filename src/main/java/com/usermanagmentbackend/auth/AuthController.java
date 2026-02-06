package com.usermanagmentbackend.auth;

import com.usermanagmentbackend.auth.dto.ChangePasswordRequest;
import com.usermanagmentbackend.auth.dto.LoginRequest;
import com.usermanagmentbackend.auth.dto.LogoutRequest;
import com.usermanagmentbackend.auth.dto.RefreshTokenRequest;
import com.usermanagmentbackend.auth.dto.RegisterRequest;
import com.usermanagmentbackend.auth.dto.RegisterResponse;
import com.usermanagmentbackend.auth.dto.ResetPasswordRequest;
import com.usermanagmentbackend.auth.dto.TokenPairResponse;
import com.usermanagmentbackend.auth.dto.UpdateAvatarRequest;
import com.usermanagmentbackend.auth.dto.UpdateProfileRequest;
import com.usermanagmentbackend.users.dto.RemindPasswordRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private final AuthService authService;

	public AuthController(final AuthService authService) {
		this.authService = authService;
	}

	@PostMapping("/register")
	@ResponseStatus(HttpStatus.CREATED)
	public RegisterResponse register(@RequestBody @Valid final RegisterRequest req) {
		return authService.register(req);
	}

	@PostMapping("/login")
	public TokenPairResponse login(@RequestBody @Valid final LoginRequest req) {
		return authService.login(req);
	}

	@PostMapping("/refresh-token")
	public TokenPairResponse refresh(@RequestBody @Valid final RefreshTokenRequest req) {
		return authService.refresh(req);
	}

	@PostMapping("/logout")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void logout(@RequestBody @Valid final LogoutRequest req) {
		authService.logout(req);
	}

	@PostMapping("/reset-password")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void resetPassword(@RequestBody final ResetPasswordRequest req) {
		authService.resetPassword(req);
	}

	@PostMapping("/remind-password")
	@ResponseStatus(HttpStatus.ACCEPTED)
	public Map<String, String> remindPassword(@RequestBody @Valid final RemindPasswordRequest req) {
		authService.remindPassword(req.email());
		return Map.of("message", "If account exists, email was sent.");
	}

	@PutMapping("/changePassword")
	@ResponseStatus(HttpStatus.ACCEPTED)
	public Map<String, String> changePassword(
			@RequestBody @Valid final ChangePasswordRequest req
	) {
		authService.changePassword(req);
		return Map.of("message", "Password changed successfully.");
	}

	@PutMapping("/updateProfile")
	@ResponseStatus(HttpStatus.ACCEPTED)
	public Map<String, String> updateProfile(
			@RequestBody @Valid final UpdateProfileRequest req
	) {
		authService.updateProfile(req);
		return Map.of("message", "Profile updated successfully.");
	}

	@PatchMapping("/avatarUpdate")
	@ResponseStatus(HttpStatus.ACCEPTED)
	public Map<String, String> updateAvatar(
			@RequestBody @Valid final UpdateAvatarRequest request
	) {
		authService.updateAvatar(request);
		return Map.of("message", "Avatar updated successfully.");
	}
}