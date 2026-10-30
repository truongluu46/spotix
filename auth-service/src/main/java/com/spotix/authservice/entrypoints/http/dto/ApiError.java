package com.spotix.authservice.entrypoints.http.dto;

import java.util.Map;

public record ApiError(String code, String message, String requestId, Map<String, String> fieldErrors) {
}
