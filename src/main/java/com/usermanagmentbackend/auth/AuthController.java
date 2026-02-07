package com.usermanagmentbackend.auth;

import com.usermanagmentbackend.auth.dto.ChangePasswordRequest;
import com.usermanagmentbackend.auth.dto.LoginRequest;
import com.usermanagmentbackend.auth.dto.LogoutRequest;
import com.usermanagmentbackend.auth.dto.RefreshTokenRequest;
import com.usermanagmentbackend.auth.dto.RegisterRequest;
import com.usermanagmentbackend.auth.dto.RegisterResponse;
import com.usermanagmentbackend.auth.dto.ResetPasswordRequest;
import com.usermanagmentbackend.auth.dto.TokenPairResponse;
import com.usermanagmentbackend.auth.dto.UpdateProfileRequest;
import com.usermanagmentbackend.auth.dto.UploadAvatarResponse;
import com.usermanagmentbackend.users.dto.RemindPasswordRequest;
import jakarta.validation.Valid;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
			@RequestBody @Valid final UploadAvatarResponse request
	) {
		authService.updateAvatar(request);
		return Map.of("message", "Avatar updated successfully.");
	}

	@PostMapping(value = "/avatar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public Map<String, String> uploadAvatar(@RequestParam("file") final MultipartFile file) {
		final String url = authService.uploadAvatar(file).toString();
		return Map.of("url", url);
	}

	@GetMapping("/avatar/show")
	public ResponseEntity<Resource> getMyAvatar(
			final Authentication authentication
	) throws IOException {
		final Path avatar =
				Paths.get("/opt/apps/myapi/uploads/avatars");
		final String userId = authentication.getName();

		final Path avatarPath = avatar.resolve(userId + ".png");

		if (!Files.exists(avatarPath)) {
			return ResponseEntity.notFound().build();
		}

		final Resource resource = new UrlResource(avatarPath.toUri());

		return ResponseEntity.ok()
				.contentType(MediaType.IMAGE_PNG)
				.cacheControl(CacheControl.noCache())
				.body(resource);
	}
}