package com.usermanagmentbackend.auth.dto;

public record TokenPairResponse(String accessToken, String refreshToken) {
}