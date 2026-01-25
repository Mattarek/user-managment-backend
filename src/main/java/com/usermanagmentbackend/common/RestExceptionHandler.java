package com.usermanagmentbackend.common;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.BindException;
import java.time.Instant;

@RestControllerAdvice
public class RestExceptionHandler {
	@ExceptionHandler(ApiException.class)
	public ResponseEntity<ApiError> handleApi(final ApiException apiException, final HttpServletRequest httpServletRequest) {
		final var body = new ApiError(Instant.now(), apiException.httpStatus().value(), apiException.code(), apiException.getMessage(), httpServletRequest.getRequestURI());
		return ResponseEntity.status(apiException.httpStatus()).body(body);
	}

	@ExceptionHandler({MethodArgumentNotValidException.class, BindException.class})
	public ResponseEntity<ApiError> handleValidation(final Exception ex, final HttpServletRequest req) {
		final var body = new ApiError(Instant.now(), 422, "VALIDATION_ERROR", "Validation failed", req.getRequestURI());
		return ResponseEntity.status(422).body(body);
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ApiError> handleOther(final Exception ex, final HttpServletRequest req) {
		final var body = new ApiError(Instant.now(), 500, "INTERNAL_ERROR", "Unexpected error", req.getRequestURI());
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
	}
}
