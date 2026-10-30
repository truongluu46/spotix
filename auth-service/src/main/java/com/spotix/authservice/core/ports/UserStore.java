package com.spotix.authservice.core.ports;

import com.spotix.authservice.core.domain.User;
import java.util.Optional;
import java.util.UUID;

public interface UserStore {
    Optional<User> findByEmail(String normalizedEmail);
    Optional<User> findById(UUID id);

    /** Empty only when the email already exists; other storage failures must propagate. */
    Optional<UUID> insert(User user);
}
