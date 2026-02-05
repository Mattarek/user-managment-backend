package com.usermanagmentbackend.auth;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class InvalidCurrentPasswordException extends RuntimeException {
	public InvalidCurrentPasswordException() {
		super("Current password is incorrect");
	}
}