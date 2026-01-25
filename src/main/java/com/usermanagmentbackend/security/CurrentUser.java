package com.usermanagmentbackend.security;

import java.util.UUID;

public record CurrentUser(UUID id, String email) {
}