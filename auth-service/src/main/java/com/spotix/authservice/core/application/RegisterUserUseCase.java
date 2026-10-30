package com.spotix.authservice.core.application;

import com.spotix.authservice.core.domain.AuthException;
import com.spotix.authservice.core.domain.User;
import com.spotix.authservice.core.domain.UserRole;
import com.spotix.authservice.core.ports.PasswordHasher;
import com.spotix.authservice.core.ports.UserStore;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.UUID;

public class RegisterUserUseCase {
    private final UserStore users;
    private final PasswordHasher passwords;
    private final Clock clock;

    public RegisterUserUseCase(UserStore users, PasswordHasher passwords, Clock clock) {
        this.users = users;
        this.passwords = passwords;
        this.clock = clock;
    }

    public UserView execute(String email, String password, String displayName) {
        int bytes = password == null ? 0 : password.getBytes(StandardCharsets.UTF_8).length;
        if (email == null || email.isBlank() || email.trim().length() > 254
                || displayName == null || displayName.trim().isEmpty()
                || displayName.trim().length() > 100 || password == null || password.isBlank()
                || bytes < 8 || bytes > 72) {
            throw new AuthException(AuthException.Code.INVALID_INPUT, "Invalid registration details");
        }
        // Hash before entering the persistence transaction.
        var user = new User(UUID.randomUUID(), email.trim().toLowerCase(Locale.ROOT),
                passwords.hash(password), displayName.trim(), UserRole.USER, true,
                clock.instant().truncatedTo(ChronoUnit.MICROS));
        if (users.insert(user).isEmpty()) {
            throw new AuthException(AuthException.Code.EMAIL_ALREADY_EXISTS, "Email already exists");
        }
        return UserView.from(user);
    }
}
