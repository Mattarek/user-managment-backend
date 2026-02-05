package com.usermanagmentbackend.domain.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "users", indexes = @Index(name = "index,users_email", columnList = "email", unique = true))
public class User {

	@Column(nullable = false)
	private final Instant createdAt = Instant.now();
	@Id
	@GeneratedValue
	private UUID id;
	@Column(nullable = false, unique = true, length = 320)
	private String email;
	@Column(nullable = false, length = 120)
	private String name;
	@Column(nullable = false, length = 120)
	private String surname;
	@Column(nullable = false, length = 200)
	private String passwordHash;

	protected User() {
	}

	public User(final String email, final String name, final String surname, final String passwordHash) {
		this.email = email.toLowerCase();
		this.name = name;
		this.surname = surname;
		this.passwordHash = passwordHash;
	}

	public void changePassword(final String newPasswordHash) {
		if (newPasswordHash == null || newPasswordHash.isBlank()) {
			throw new IllegalArgumentException("Password hash cannot be null or blank");
		}
		passwordHash = newPasswordHash;
	}

	public UUID getId() {
		return id;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(final String email) {
		if (email == null || email.isBlank()) {
			throw new IllegalArgumentException("Email cannot be null or blank");
		}
		this.email = email.toLowerCase();
	}

	public Instant getCreatedAt() {
		return createdAt;
	}

	public String getName() {
		return name;
	}

	public void setName(final String name) {
		if (name == null || name.isBlank()) {
			throw new IllegalArgumentException("Name cannot be null or blank");
		}
		this.name = name;
	}

	public String getSurname() {
		return surname;
	}

	public void setSurname(final String surname) {
		if (surname == null || surname.isBlank()) {
			throw new IllegalArgumentException("Surname cannot be null or blank");
		}
		this.surname = surname;
	}

	public void changeProfile(final String email, final String name, final String surname) {
		if (email == null || email.isBlank()) {
			throw new IllegalArgumentException("Email cannot be null or blank");
		}
		if (name == null || name.isBlank()) {
			throw new IllegalArgumentException("Name cannot be null or blank");
		}
		if (surname == null || surname.isBlank()) {
			throw new IllegalArgumentException("Surname cannot be null or blank");
		}

		this.email = email.toLowerCase();
		this.name = name;
		this.surname = surname;
	}

	public String getPasswordHash() {
		return passwordHash;
	}

	public void setPasswordHash(final String passwordHash) {
		this.passwordHash = passwordHash;
	}

	public void setPassword(@Nullable final String passwordHash) {
		if (passwordHash == null || passwordHash.isBlank()) {
			throw new IllegalArgumentException("Password hash cannot be null or blank");
		}
		this.passwordHash = passwordHash;
	}
}
