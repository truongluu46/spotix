package com.spotix.authservice.configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.*;
import java.io.IOException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtConfiguration {
    @Bean
    RSAPublicKey publicKey(JwtProperties properties) throws IOException {
        try (var input = properties.publicKey().getInputStream()) {
            var key = RsaKeyConverters.x509().convert(input);
            if (key == null || key.getModulus().bitLength() < 2048) {
                throw new IllegalArgumentException("JWT public key must be RSA with at least 2048 bits");
            }
            return key;
        }
    }

    @Bean
    JwtEncoder jwtEncoder(JwtProperties properties, RSAPublicKey publicKey) throws IOException {
        RSAPrivateKey privateKey;
        try (var input = properties.privateKey().getInputStream()) {
            privateKey = RsaKeyConverters.pkcs8().convert(input);
        }
        if (!(privateKey instanceof RSAPrivateCrtKey crt)
                || !crt.getModulus().equals(publicKey.getModulus())
                || !crt.getPublicExponent().equals(publicKey.getPublicExponent())) {
            throw new IllegalArgumentException("JWT private and public keys must be a matching RSA pair");
        }
        var key = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
    }

    @Bean
    JwtDecoder jwtDecoder(JwtProperties properties, RSAPublicKey publicKey) {
        var decoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
        OAuth2TokenValidator<Jwt> claims = jwt -> {
            try {
                UUID.fromString(jwt.getSubject());
                Object roles = jwt.getClaims().get("roles");
                if (jwt.getExpiresAt() == null || jwt.getIssuedAt() == null
                        || !jwt.getAudience().contains(properties.audience())
                        || !(roles instanceof List<?> values) || values.isEmpty()
                        || values.stream().anyMatch(v -> !"USER".equals(v) && !"ADMIN".equals(v))) {
                    return invalidClaims();
                }
                return OAuth2TokenValidatorResult.success();
            } catch (RuntimeException exception) {
                return invalidClaims();
            }
        };
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(Duration.ZERO), new JwtIssuerValidator(properties.issuer()), claims));
        return decoder;
    }

    private static OAuth2TokenValidatorResult invalidClaims() {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Invalid JWT claims", null));
    }
}
