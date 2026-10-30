package com.spotix.authservice.entrypoints.http.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.nio.charset.StandardCharsets;

public class Utf8PasswordValidator implements ConstraintValidator<Utf8Password, String> {
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isBlank()) {
            return false;
        }
        int bytes = value.getBytes(StandardCharsets.UTF_8).length;
        return bytes >= 8 && bytes <= 72;
    }
}
