package com.usermanagmentbackend.auth.dto;

public record ResetPasswordRequest(String password, String token) {
}
