package com.spotix.authservice.configuration;

import jakarta.validation.constraints.*;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(@NotBlank String issuer, @NotBlank String audience,
                            @Min(60) @Max(86400) long accessTokenSeconds,
                            @NotNull Resource privateKey, @NotNull Resource publicKey) {
}
