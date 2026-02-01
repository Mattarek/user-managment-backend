package com.usermanagmentbackend.domain.reset;

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
@Table(name = "password_reset_tokens", indexes = {
		@Index(name = "idx_prt_hash", columnList = "tokenHash", unique = true),
		@Index(name = "idx_prt_user", columnList = "user_id")
})
public class PasswordResetToken {

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
	private Instant usedAt;

	protected PasswordResetToken() {
	}

	public PasswordResetToken(final User user, final String tokenHash, final Instant expiresAt) {
		this.user = user;
		this.tokenHash = tokenHash;
		this.expiresAt = expiresAt;
	}

	public boolean isExpired(final Instant now) {
		return now.isAfter(expiresAt);
	}

	public boolean isUsed() {
		return usedAt != null;
	}

	public void markUsed(final Instant now) {
		usedAt = now;
	}

	public User getUser() {
		return user;
	}

	public Instant getExpiresAt() {
		return expiresAt;
	}
}