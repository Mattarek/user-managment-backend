package com.usermanagmentbackend.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
		@Email @NotBlank String email,
		@NotBlank @Size(min = 2) String name,
		@NotBlank @Size(min = 2) String surname,
		@NotBlank @Size(min = 10) String password,
		@NotBlank @Size(min = 10) String repeatedPassword
) {
}