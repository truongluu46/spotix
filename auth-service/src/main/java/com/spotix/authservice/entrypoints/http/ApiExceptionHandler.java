package com.spotix.authservice.entrypoints.http;

import com.spotix.authservice.core.domain.AuthException;
import com.spotix.authservice.entrypoints.http.dto.ApiError;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.transaction.TransactionException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class ApiExceptionHandler {
    private static final Logger LOG = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(AuthException.class)
    ResponseEntity<ApiError> auth(AuthException ex, HttpServletRequest request, HttpServletResponse response) {
        int status = switch (ex.code()) {
            case EMAIL_ALREADY_EXISTS -> 409;
            case INVALID_CREDENTIALS, USER_UNAVAILABLE -> 401;
            case INVALID_INPUT -> 400;
        };
        if (status == 401) {
            response.setHeader("WWW-Authenticate", "Bearer");
        }
        return error(status, ex.code().name(), ex.getMessage(), request, Map.of());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ApiError> validation(MethodArgumentNotValidException ex, HttpServletRequest request) {
        Map<String, String> fields = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(e -> fields.putIfAbsent(e.getField(), e.getDefaultMessage()));
        return error(400, "VALIDATION_ERROR", "Invalid request fields", request, fields);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<ApiError> malformed(HttpServletRequest request) {
        return error(400, "INVALID_REQUEST", "Malformed JSON or unexpected request fields", request, Map.of());
    }

    @ExceptionHandler({DataAccessException.class, TransactionException.class})
    ResponseEntity<ApiError> storage(RuntimeException ex, HttpServletRequest request) {
        LOG.error("Database operation failed; requestId={}", request.getAttribute(RequestIdFilter.ATTRIBUTE), ex);
        return error(503, "SERVICE_UNAVAILABLE", "Storage is temporarily unavailable", request, Map.of());
    }

    private ResponseEntity<ApiError> error(int status, String code, String message,
                                           HttpServletRequest request, Map<String, String> fields) {
        return ResponseEntity.status(status).body(new ApiError(code, message,
                (String) request.getAttribute(RequestIdFilter.ATTRIBUTE), fields));
    }
}
