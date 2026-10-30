package com.spotix.authservice.entrypoints.http.dto;

import jakarta.validation.constraints.*;

public record LoginRequest(@NotBlank @Email @Size(max = 254) String email,
                           @NotBlank @Size(max = 72) String password) {
    public LoginRequest {
        email = email == null ? null : email.trim();
    }

    @Override
    public String toString() {
        return "LoginRequest[redacted]";
    }
}
