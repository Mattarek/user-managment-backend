package com.usermanagmentbackend.auth;

import com.usermanagmentbackend.auth.dto.LoginRequest;
import com.usermanagmentbackend.auth.dto.LogoutRequest;
import com.usermanagmentbackend.auth.dto.RefreshTokenRequest;
import com.usermanagmentbackend.auth.dto.RegisterRequest;
import com.usermanagmentbackend.auth.dto.RegisterResponse;
import com.usermanagmentbackend.auth.dto.ResetPasswordRequest;
import com.usermanagmentbackend.auth.dto.TokenPairResponse;
import com.usermanagmentbackend.common.ApiException;
import com.usermanagmentbackend.domain.reset.PasswordResetToken;
import com.usermanagmentbackend.domain.reset.PasswordResetTokenRepository;
import com.usermanagmentbackend.domain.token.RefreshToken;
import com.usermanagmentbackend.domain.token.RefreshTokenRepository;
import com.usermanagmentbackend.domain.user.User;
import com.usermanagmentbackend.domain.user.UserRepository;
import com.usermanagmentbackend.security.JwtService;
import com.usermanagmentbackend.util.TokenHasher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

@Service
public class AuthServiceImpl implements AuthService {

	private final UserRepository userRepository;
	private final RefreshTokenRepository refreshTokenRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final SecureRandom secureRandom = new SecureRandom();
	private final PasswordResetTokenRepository passwordResetTokenRepository;
	private final int refreshTtlDays;

	public AuthServiceImpl(
			final UserRepository userRepository,
			final RefreshTokenRepository refreshTokenRepository,
			final PasswordEncoder passwordEncoder,
			final JwtService jwtService, final PasswordResetTokenRepository passwordResetTokenRepository,
			@Value("${app.jwt.refreshTtlDays}") final int refreshTtlDays
	) {
		this.userRepository = userRepository;
		this.refreshTokenRepository = refreshTokenRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.passwordResetTokenRepository = passwordResetTokenRepository;
		this.refreshTtlDays = refreshTtlDays;
	}

	@Override
	@Transactional
	public RegisterResponse register(final RegisterRequest req) {
		final String email = req.email().toLowerCase();

		if (!req.password().equals(req.repeatedPassword())) {
			throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "PASSWORD_MISMATCH", "Passwords do not match");
		}
		if (userRepository.existsByEmail(email)) {
			throw new ApiException(HttpStatus.CONFLICT, "EMAIL_TAKEN", "Email is already taken");
		}

		final String hash = passwordEncoder.encode(req.password());
		final User user = userRepository.save(new User(email, req.name(), req.surname(), hash));

		return new RegisterResponse(user.getId(), user.getEmail(), user.getName(), user.getSurname());
	}

	@Override
	@Transactional
	public TokenPairResponse login(final LoginRequest req) {
		final String email = req.email().toLowerCase();
		final User user = userRepository.findByEmail(email)
				.orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "Invalid credentials"));

		if (!passwordEncoder.matches(req.password(), user.getPasswordHash())) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "Invalid credentials");
		}

		final String access = jwtService.createAccessToken(user);
		final String refreshRaw = generateOpaqueToken();
		final String refreshHash = TokenHasher.sha256Hex(refreshRaw);

		final Instant exp = Instant.now().plus(refreshTtlDays, ChronoUnit.DAYS);
		refreshTokenRepository.save(new RefreshToken(user, refreshHash, exp));

		return new TokenPairResponse(access, refreshRaw);
	}

	@Override
	@Transactional
	public TokenPairResponse refresh(final RefreshTokenRequest req) {
		final String refreshRaw = req.refreshToken();
		final String hash = TokenHasher.sha256Hex(refreshRaw);

		final RefreshToken existing = refreshTokenRepository.findByTokenHash(hash)
				.orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "REFRESH_INVALID_OR_EXPIRED", "Refresh token invalid"));

		final Instant now = Instant.now();
		if (existing.isRevoked() || existing.isExpired(now)) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "REFRESH_INVALID_OR_EXPIRED", "Refresh token invalid");
		}

		existing.revoke(now);

		final User user = existing.getUser();
		final String newAccess = jwtService.createAccessToken(user);

		final String newRefreshRaw = generateOpaqueToken();
		final String newRefreshHash = TokenHasher.sha256Hex(newRefreshRaw);
		final Instant exp = now.plus(refreshTtlDays, ChronoUnit.DAYS);
		refreshTokenRepository.save(new RefreshToken(user, newRefreshHash, exp));

		return new TokenPairResponse(newAccess, newRefreshRaw);
	}

	@Override
	@Transactional
	public void logout(final LogoutRequest req) {
		final String hash = TokenHasher.sha256Hex(req.refreshToken());
		refreshTokenRepository.findByTokenHash(hash).ifPresent(rt -> rt.revoke(Instant.now()));
	}

	private String generateOpaqueToken() {
		final byte[] buf = new byte[48];
		secureRandom.nextBytes(buf);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
	}

	@Transactional
	public ResetPasswordRequest resetPassword(final ResetPasswordRequest req) {
		if (req == null || req.password() == null || req.token() == null) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
		}
		if (req.password().length() < 10) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password too short");
		}

		final String tokenHash = TokenHasher.sha256Hex(req.token());

		final PasswordResetToken passwordResetToken = passwordResetTokenRepository
				.findByTokenHash(tokenHash)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST));

		if (passwordResetToken.getExpiresAt().isBefore(Instant.now())) {
			passwordResetTokenRepository.delete(passwordResetToken);
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
		}

		final User user = passwordResetToken.getUser();
		user.setPassword(passwordEncoder.encode(req.password()));
		userRepository.save(user);

		passwordResetTokenRepository.delete(passwordResetToken);
		return req;
	}
}