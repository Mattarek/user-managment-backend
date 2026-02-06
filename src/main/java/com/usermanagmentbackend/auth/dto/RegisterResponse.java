package com.usermanagmentbackend.auth.dto;

import java.util.UUID;

public record RegisterResponse(UUID id, String email, String name, String surname, String avatarUrl) {
}