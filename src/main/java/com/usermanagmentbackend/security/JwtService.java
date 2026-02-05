package com.usermanagmentbackend.security;

import com.usermanagmentbackend.domain.user.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

	private static final int SECRET_LENGTH = 32;
	private final SecretKey key;
	private final int accessTtlMinutes;

	public JwtService(
			@Value("${app.jwt.secret}") final String secret,
			@Value("${app.jwt.accessTtlMinutes}") final int accessTtlMinutes
	) {
		if (secret == null || secret.length() < SECRET_LENGTH) {
			throw new IllegalStateException("app.jwt.secret must be at least " + SECRET_LENGTH + " chars");
		}
		key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
		this.accessTtlMinutes = accessTtlMinutes;
	}

	public String createAccessToken(final User user) {
		final Instant now = Instant.now();
		final Instant exp = now.plusSeconds(accessTtlMinutes * 60L);

		return Jwts.builder()
				.subject(user.getEmail())
				.claim("uid", user.getId().toString())
				.issuedAt(Date.from(now))
				.expiration(Date.from(exp))
				.signWith(key)
				.compact();
	}

	public CurrentUser parseAccessToken(final String token) {
		try {
			final Claims c = Jwts.parser()
					.verifyWith(key)
					.build()
					.parseSignedClaims(token)
					.getPayload();

			final String email = c.getSubject();
			final String uid = c.get("uid", String.class);

			if (email == null || uid == null) {
				return null;
			}

			return new CurrentUser(UUID.fromString(uid), email);
		} catch (final JwtException | IllegalArgumentException e) {
			return null;
		}
	}
}