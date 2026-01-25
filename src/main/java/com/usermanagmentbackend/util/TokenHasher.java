package com.usermanagmentbackend.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

public class TokenHasher {
	private static final HexFormat HEX = HexFormat.of();

	private TokenHasher() {
	}

	public static String sha256Hex(final String token) {
		try {
			final var messageDigest = MessageDigest.getInstance("SHA-256");
			final byte[] digest = messageDigest.digest(token.getBytes(StandardCharsets.UTF_8));
			return HEX.formatHex(digest);
		} catch (final Exception e) {
			throw new IllegalStateException("Cannot hash token", e);
		}
	}
}
