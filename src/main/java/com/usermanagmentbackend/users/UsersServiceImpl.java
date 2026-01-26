package com.usermanagmentbackend.users;

import com.usermanagmentbackend.common.ApiException;
import com.usermanagmentbackend.domain.reset.PasswordResetToken;
import com.usermanagmentbackend.domain.reset.PasswordResetTokenRepository;
import com.usermanagmentbackend.domain.user.UserRepository;
import com.usermanagmentbackend.mail.MailService;
import com.usermanagmentbackend.security.CurrentUser;
import com.usermanagmentbackend.users.dto.MeResponse;
import com.usermanagmentbackend.util.TokenHasher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

@Service
public class UsersServiceImpl implements UsersService {

	private final UserRepository userRepository;
	private final PasswordResetTokenRepository passwordResetTokenRepository;
	private final MailService mailService;
	private final SecureRandom secureRandom = new SecureRandom();

	private final int resetTtlMinutes;
	private final String resetLinkBase;

	public UsersServiceImpl(
			final UserRepository userRepository,
			final PasswordResetTokenRepository passwordResetTokenRepository,
			final MailService mailService,
			@Value("${app.passwordReset.ttlMinutes}") final int resetTtlMinutes,
			@Value("${app.passwordReset.linkBase}") final String resetLinkBase
	) {
		this.userRepository = userRepository;
		this.passwordResetTokenRepository = passwordResetTokenRepository;
		this.mailService = mailService;
		this.resetTtlMinutes = resetTtlMinutes;
		this.resetLinkBase = resetLinkBase;
	}

	@Override
	@Transactional(readOnly = true)
	public MeResponse getMe() {
		final var auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth == null || !(auth.getPrincipal() instanceof final CurrentUser cu)) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
		}

		final var user = userRepository.findByEmail(cu.email().toLowerCase())
				.orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized"));

		return new MeResponse(user.getEmail(), user.getEmail(), user.getName(), user.getSurname());
	}

	@Override
	@Transactional
	public void remindPassword(final String email) {
		userRepository.findByEmail(email.toLowerCase()).ifPresent(user -> {
			final String raw = generateOpaqueToken();
			final String hash = TokenHasher.sha256Hex(raw);
			final Instant exp = Instant.now().plus(resetTtlMinutes, ChronoUnit.MINUTES);
			passwordResetTokenRepository.save(new PasswordResetToken(user, hash, exp));

			final String link = resetLinkBase + raw;
			System.out.println(link);
			mailService.sendPasswordReset(user.getEmail(), link);
		});
	}

	private String generateOpaqueToken() {
		final byte[] buf = new byte[48];
		secureRandom.nextBytes(buf);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
	}
}