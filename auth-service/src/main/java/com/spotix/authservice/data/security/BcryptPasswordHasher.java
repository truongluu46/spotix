package com.spotix.authservice.data.security;

import com.spotix.authservice.core.ports.PasswordHasher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;

@Component
public class BcryptPasswordHasher implements PasswordHasher {
    private final PasswordEncoder encoder;

    public BcryptPasswordHasher(PasswordEncoder encoder) {
        this.encoder = encoder;
    }

    @Override
    public String hash(String password) {
        return encoder.encode(password);
    }

    @Override
    public boolean matches(String password, String hash) {
        return password != null && password.getBytes(StandardCharsets.UTF_8).length <= 72
                && encoder.matches(password, hash);
    }
}
