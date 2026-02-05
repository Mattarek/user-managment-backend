package com.usermanagmentbackend.common;

import org.springframework.http.HttpStatusCode;

public class ApiException extends RuntimeException {
	private final HttpStatusCode httpStatusCode;
	private final String code;

	public ApiException(final HttpStatusCode httpStatusCode, final String code, final String message) {
		super(message);
		this.httpStatusCode = httpStatusCode;
		this.code = code;
	}

	public HttpStatusCode httpStatus() {
		return httpStatusCode;
	}

	public String code() {
		return code;
	}
}
