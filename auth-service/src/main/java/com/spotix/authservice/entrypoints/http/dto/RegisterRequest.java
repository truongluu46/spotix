package com.spotix.authservice.entrypoints.http.dto;

import jakarta.validation.constraints.*;
import com.spotix.authservice.entrypoints.http.validation.Utf8Password;

public record RegisterRequest(@NotBlank @Email @Size(max = 254) String email,
                              @Utf8Password String password,
                              @NotBlank @Size(max = 100) String displayName) {
    public RegisterRequest {
        email = email == null ? null : email.trim();
        displayName = displayName == null ? null : displayName.trim();
    }

    @Override
    public String toString() {
        return "RegisterRequest[redacted]";
    }
}
