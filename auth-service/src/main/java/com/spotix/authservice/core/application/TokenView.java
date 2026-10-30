package com.spotix.authservice.core.application;

public record TokenView(String accessToken, String tokenType, long expiresIn, UserView user) {
    @Override
    public String toString() {
        return "TokenView[tokenType=" + tokenType + ", expiresIn=" + expiresIn + "]";
    }
}
