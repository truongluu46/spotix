package com.spotix.authservice.core.domain;

public class AuthException extends RuntimeException {
    public enum Code { EMAIL_ALREADY_EXISTS, INVALID_CREDENTIALS, USER_UNAVAILABLE, INVALID_INPUT }

    private final Code code;

    public AuthException(Code code, String message) {
        super(message);
        this.code = code;
    }

    public Code code() {
        return code;
    }
}
