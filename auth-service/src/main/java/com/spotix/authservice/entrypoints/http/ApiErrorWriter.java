package com.spotix.authservice.entrypoints.http;

import com.spotix.authservice.entrypoints.http.dto.ApiError;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
public class ApiErrorWriter {
    private final ObjectMapper mapper;

    public ApiErrorWriter(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public void write(HttpServletRequest request, HttpServletResponse response,
                      int status, String code, String message) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        if (status == 401) {
            response.setHeader("WWW-Authenticate", "Bearer");
        }
        mapper.writeValue(response.getOutputStream(), new ApiError(code, message,
                (String) request.getAttribute(RequestIdFilter.ATTRIBUTE), Map.of()));
    }
}
