package com.usermanagmentbackend.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class ChangePasswordRequest {

	@NotBlank
	private String currentPassword;

	@NotBlank
	@Size(min = 10)
	private String newPassword;

	public String getCurrentPassword() {
		return currentPassword;
	}

	public String getNewPassword() {
		return newPassword;
	}
}