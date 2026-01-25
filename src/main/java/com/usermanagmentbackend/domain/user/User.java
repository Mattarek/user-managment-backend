package com.usermanagmentbackend.domain.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

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

	public UUID getId() {
		return id;
	}

	public String getEmail() {
		return email;
	}

	public String getName() {
		return name;
	}

	public String getSurname() {
		return surname;
	}

	public String getPasswordHash() {
		return passwordHash;
	}
}
