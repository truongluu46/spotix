package com.spotix.authservice.core.application;

import com.spotix.authservice.core.domain.User;
import com.spotix.authservice.core.domain.UserRole;
import java.time.Instant;
import java.util.UUID;

public record UserView(UUID id, String email, String displayName, UserRole role, Instant createdAt) {
    public static UserView from(User user) {
        return new UserView(user.id(), user.email(), user.displayName(), user.role(), user.createdAt());
    }
}
