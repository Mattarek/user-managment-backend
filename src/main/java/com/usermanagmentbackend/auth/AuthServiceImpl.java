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
import com.usermanagmentbackend.common.ApiException;
import com.usermanagmentbackend.domain.reset.PasswordResetToken;
import com.usermanagmentbackend.domain.reset.PasswordResetTokenRepository;
import com.usermanagmentbackend.domain.token.RefreshToken;
import com.usermanagmentbackend.domain.token.RefreshTokenRepository;
import com.usermanagmentbackend.domain.user.User;
import com.usermanagmentbackend.domain.user.UserRepository;
import com.usermanagmentbackend.mail.MailService;
import com.usermanagmentbackend.security.CurrentUser;
import com.usermanagmentbackend.security.JwtService;
import com.usermanagmentbackend.util.TokenHasher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthServiceImpl implements AuthService {

	private final UserRepository userRepository;
	private final RefreshTokenRepository refreshTokenRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final SecureRandom secureRandom = new SecureRandom();
	private final PasswordResetTokenRepository passwordResetTokenRepository;
	private final int refreshTtlDays;
	private final MailService mailService;
	private final Path avatarsDir;
	private final int resetTtlMinutes;
	private final String resetLinkBase;

	public AuthServiceImpl(
			final UserRepository userRepository,
			final RefreshTokenRepository refreshTokenRepository,
			final PasswordEncoder passwordEncoder,
			final JwtService jwtService, final PasswordResetTokenRepository passwordResetTokenRepository,
			@Value("${app.jwt.refreshTtlDays}") final int refreshTtlDays, final MailService mailService,
			@Value("${app.passwordReset.ttlMinutes}") final int resetTtlMinutes,
			@Value("${app.passwordReset.linkBase}") final String resetLinkBase,
			@Value("/opt/apps/myapi/uploads/avatars") final String avatarsDir
	) {
		this.userRepository = userRepository;
		this.refreshTokenRepository = refreshTokenRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.passwordResetTokenRepository = passwordResetTokenRepository;
		this.refreshTtlDays = refreshTtlDays;
		this.mailService = mailService;
		this.resetTtlMinutes = resetTtlMinutes;
		this.resetLinkBase = resetLinkBase;
		this.avatarsDir = Paths.get(avatarsDir);
	}

	@Override
	public Object uploadAvatar(final MultipartFile file) {
		// 1) Walidacja pliku
		if (file == null || file.isEmpty()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "File is empty");
		}

		// Spójność z /avatar/show -> zapisujemy jako .png
		final String contentType = file.getContentType();
		if (contentType == null || !contentType.equalsIgnoreCase("image/png")) {
			throw new ResponseStatusException(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "Only PNG is allowed");
		}

		// limit np. 5MB (możesz zmienić)
		final long maxSize = 5L * 1024 * 1024;
		if (file.getSize() > maxSize) {
			throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "Max file size is 5MB");
		}

		// 2) Wyciągnięcie userId z SecurityContext
		final UUID userId = getCurrentUserId();

		// 3) Zapis na dysk: {uuid}.png (atomowo przez temp + move)
		try {
			Files.createDirectories(avatarsDir);

			final Path target = avatarsDir.resolve(userId + ".png");
			final Path tmp = avatarsDir.resolve(userId + ".png.tmp");

			// copy -> tmp (nadpisz)
			Files.copy(file.getInputStream(), tmp, StandardCopyOption.REPLACE_EXISTING);

			// move tmp -> target (nadpisz, atomic jeśli FS pozwala)
			try {
				Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
			} catch (final AtomicMoveNotSupportedException ex) {
				Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
			}
		} catch (final IOException e) {
			throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to save avatar", e);
		}

		// 4) Zwróć URL do odczytu (relative; front sobie dołączy baseURL)
		// (dodałem cache-busting, żeby po uploadzie od razu widać było zmianę)
		return "/api/auth/avatar/show?ts=" + System.currentTimeMillis();
	}

	private UUID getCurrentUserId() {
		final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth == null || auth.getPrincipal() == null) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Not authenticated");
		}

		final Object principal = auth.getPrincipal();
		if (!(principal instanceof final CurrentUser currentUser) || currentUser.id() == null) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid principal");
		}

		return currentUser.id();
	}

	@Override
	@Transactional
	public RegisterResponse register(final RegisterRequest req) {
		final String email = req.email().toLowerCase();

		if (!req.password().equals(req.repeatedPassword())) {
			throw new ApiException(
					HttpStatusCode.valueOf(422),
					"PASSWORD_MISMATCH",
					"Passwords do not match"
			);
		}

		if (userRepository.existsByEmail(email)) {
			throw new ApiException(
					HttpStatus.CONFLICT,
					"EMAIL_TAKEN",
					"Email is already taken"
			);
		}

		final String hash = passwordEncoder.encode(req.password());
		final User user = userRepository.save(
				new User(email, req.name(), req.surname(), hash)
		);

		return new RegisterResponse(
				user.getId(),
				user.getEmail(),
				user.getName(),
				user.getSurname(),
				user.getAvatarUrl()
		);
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

	@Override
	@Transactional
	public void changePassword(final ChangePasswordRequest req) {
		final User user = getCurrentUser();

		if (!passwordEncoder.matches(req.getCurrentPassword(), user.getPasswordHash())) {
			throw new InvalidCurrentPasswordException();
		}

		user.changePassword(passwordEncoder.encode(req.getNewPassword()));
		userRepository.save(user);
	}

	@Override
	@Transactional
	public void updateProfile(final UpdateProfileRequest req) {
		final User user = getCurrentUser();

		if (!user.getEmail().equalsIgnoreCase(req.getEmail())
				&& userRepository.existsByEmailIgnoreCase(req.getEmail())) {
			throw new IllegalArgumentException("Email is already taken");
		}

		user.changeProfile(
				req.getEmail(),
				req.getName(),
				req.getSurname()
		);

		userRepository.save(user);
	}

	public User getCurrentUser() {
		final var auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth == null || !(auth.getPrincipal() instanceof CurrentUser(final UUID id, final String email))) {
			throw new IllegalStateException("Authenticated user not found");
		}

		return userRepository.findById(id)
				.orElseThrow(() -> new IllegalStateException(
						"Authenticated user not found for id=" + id + ", email=" + email
				));
	}

	@Override
	@Transactional
	public void remindPassword(final String email) {
		userRepository.findByEmail(email.toLowerCase()).ifPresent(user -> {
			final String raw = generateOpaqueToken();
			final String hash = TokenHasher.sha256Hex(raw);
			final Instant exp = Instant.now().plus(resetTtlMinutes, ChronoUnit.MINUTES);
			passwordResetTokenRepository.save(new PasswordResetToken(user, hash, exp));

			final String link = resetLinkBase + "/" + raw;
			mailService.sendPasswordReset(user.getEmail(), link);
		});
	}

	private String generateOpaqueToken() {
		final byte[] buf = new byte[48];
		secureRandom.nextBytes(buf);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
	}

	@Transactional
	public void updateAvatar(final UploadAvatarResponse request) {
		final var auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth == null || !(auth.getPrincipal() instanceof final CurrentUser currentUser)) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
		}

		final var user = userRepository.findByEmail(currentUser.email().toLowerCase())
				.orElseThrow(() -> new ApiException(
						HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized"
				));

		user.setAvatarUrl(request.url());
		userRepository.save(user);
	}

	@Override
	public Optional<Resource> getAvatarForUser(final UUID userId) {
		final Path avatarPath = avatarsDir.resolve(userId + ".png");

		if (!Files.exists(avatarPath) || !Files.isRegularFile(avatarPath)) {
			return Optional.empty();
		}

		try {
			final Resource resource = new UrlResource(avatarPath.toUri());
			return Optional.of(resource);
		} catch (final MalformedURLException e) {
			throw new IllegalStateException("Invalid avatar path: " + avatarPath, e);
		}
	}
}