package com.spotix.authservice.core.ports;

public interface PasswordHasher {
    String hash(String password);
    boolean matches(String password, String hash);
}
