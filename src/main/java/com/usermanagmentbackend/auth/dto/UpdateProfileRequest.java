package com.usermanagmentbackend.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class UpdateProfileRequest {

	@Email
	@NotBlank
	private String email;

	@NotBlank
	private String name;

	@NotBlank
	private String surname;

	public String getEmail() {
		return email;
	}

	public String getName() {
		return name;
	}

	public String getSurname() {
		return surname;
	}
}