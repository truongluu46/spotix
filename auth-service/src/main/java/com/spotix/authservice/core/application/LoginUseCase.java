package com.spotix.authservice.core.application;

import com.spotix.authservice.core.domain.AuthException;
import com.spotix.authservice.core.ports.PasswordHasher;
import com.spotix.authservice.core.ports.TokenIssuer;
import com.spotix.authservice.core.ports.UserStore;
import java.util.Locale;

public class LoginUseCase {
    private final UserStore users;
    private final PasswordHasher passwords;
    private final TokenIssuer tokens;
    private final String dummyHash;

    public LoginUseCase(UserStore users, PasswordHasher passwords, TokenIssuer tokens) {
        this.users = users;
        this.passwords = passwords;
        this.tokens = tokens;
        this.dummyHash = passwords.hash("Dummy-password-for-timing-only");
    }

    public TokenView execute(String email, String password) {
        var user = users.findByEmail(email.trim().toLowerCase(Locale.ROOT));
        boolean matches = passwords.matches(password, user.map(u -> u.passwordHash()).orElse(dummyHash));
        if (user.isEmpty() || !matches || !user.get().enabled()) {
            throw new AuthException(AuthException.Code.INVALID_CREDENTIALS, "Invalid email or password");
        }
        return tokens.issue(UserView.from(user.get()));
    }
}
