package com.usermanagmentbackend.auth.dto;

import jakarta.validation.constraints.Size;

public record UpdateAvatarRequest(@Size(max = 512)
								  String avatarUrl) {
}
