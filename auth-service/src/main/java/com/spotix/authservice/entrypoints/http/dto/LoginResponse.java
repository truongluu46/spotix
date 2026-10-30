package com.spotix.authservice.entrypoints.http.dto;

import com.spotix.authservice.core.application.TokenView;

public record LoginResponse(String accessToken, String tokenType, long expiresIn, UserResponse user) {
    public static LoginResponse from(TokenView token) {
        return new LoginResponse(token.accessToken(), token.tokenType(), token.expiresIn(),
                UserResponse.from(token.user()));
    }

    @Override
    public String toString() {
        return "LoginResponse[redacted]";
    }
}
