package com.usermanagmentbackend.users.dto;

public record MeResponse(String email, String login, String name, String surname, String avatarUrl) {
}