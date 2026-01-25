package com.usermanagmentbackend.common;

import org.springframework.http.HttpStatus;

public class ApiException extends RuntimeException {
	private final HttpStatus httpStatus;
	private final String code;

	public ApiException(final HttpStatus httpStatus, final String code, final String message) {
		super(message);
		this.httpStatus = httpStatus;
		this.code = code;
	}

	public HttpStatus httpStatus() {
		return httpStatus;
	}

	public String code() {
		return code;
	}
}
