package com.spotix.authservice.entrypoints.http.dto;

import com.spotix.authservice.core.application.UserView;
import com.spotix.authservice.core.domain.UserRole;
import java.time.Instant;
import java.util.UUID;

public record UserResponse(UUID id, String email, String displayName, UserRole role, Instant createdAt) {
    public static UserResponse from(UserView user) {
        return new UserResponse(user.id(), user.email(), user.displayName(), user.role(), user.createdAt());
    }
}
