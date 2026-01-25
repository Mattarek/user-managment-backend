package com.usermanagmentbackend.domain.token;

import com.usermanagmentbackend.domain.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens", indexes = {
		@Index(name = "idx_rt_user", columnList = "user_id"),
		@Index(name = "idx_rt_hash", columnList = "tokenHash", unique = true)
})
public class RefreshToken {

	@Column(nullable = false)
	private final Instant createdAt = Instant.now();
	@Id
	@GeneratedValue
	private UUID id;
	@ManyToOne(optional = false, fetch = FetchType.LAZY)
	private User user;
	@Column(nullable = false, unique = true, length = 64)
	private String tokenHash;
	@Column(nullable = false)
	private Instant expiresAt;
	private Instant revokedAt;

	protected RefreshToken() {
	}

	public RefreshToken(final User user, final String tokenHash, final Instant expiresAt) {
		this.user = user;
		this.tokenHash = tokenHash;
		this.expiresAt = expiresAt;
	}

	public UUID getId() {
		return id;
	}

	public User getUser() {
		return user;
	}

	public String getTokenHash() {
		return tokenHash;
	}

	public Instant getExpiresAt() {
		return expiresAt;
	}

	public Instant getRevokedAt() {
		return revokedAt;
	}

	public boolean isRevoked() {
		return revokedAt != null;
	}

	public boolean isExpired(final Instant now) {
		return now.isAfter(expiresAt);
	}

	public void revoke(final Instant now) {
		revokedAt = now;
	}
}