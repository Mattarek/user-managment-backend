package com.usermanagmentbackend.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app")
public record AppProperties(
		Jwt jwt,
		PasswordReset passwordReset,
		Mail mail
) {
	public record Jwt(String secret, int accessTtlMinutes, int refreshTtlDays) {
	}

	public record PasswordReset(int ttlMinutes, String linkBase) {
	}

	public record Mail(boolean enabled, String from, String replyTo) {
	}
}