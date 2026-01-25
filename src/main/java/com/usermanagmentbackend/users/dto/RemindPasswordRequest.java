package com.usermanagmentbackend.users.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record RemindPasswordRequest(@Email @NotBlank String email) {
}