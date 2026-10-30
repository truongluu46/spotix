package com.spotix.authservice.core.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record User(UUID id, String email, String passwordHash, String displayName,
                   UserRole role, boolean enabled, Instant createdAt) {
    public User {
        Objects.requireNonNull(id);
        Objects.requireNonNull(email);
        Objects.requireNonNull(passwordHash);
        Objects.requireNonNull(displayName);
        Objects.requireNonNull(role);
        Objects.requireNonNull(createdAt);
    }

    @Override
    public String toString() {
        return "User[id=" + id + ", role=" + role + ", enabled=" + enabled + "]";
    }
}
