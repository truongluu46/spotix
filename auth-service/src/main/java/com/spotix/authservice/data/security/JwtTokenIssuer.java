package com.spotix.authservice.data.security;

import com.spotix.authservice.configuration.JwtProperties;
import com.spotix.authservice.core.application.TokenView;
import com.spotix.authservice.core.application.UserView;
import com.spotix.authservice.core.ports.TokenIssuer;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;
import java.time.Clock;
import java.util.List;

@Component
public class JwtTokenIssuer implements TokenIssuer {
    private final JwtEncoder encoder;
    private final JwtProperties properties;
    private final Clock clock;

    public JwtTokenIssuer(JwtEncoder encoder, JwtProperties properties, Clock clock) {
        this.encoder = encoder;
        this.properties = properties;
        this.clock = clock;
    }

    @Override
    public TokenView issue(UserView user) {
        var now = clock.instant();
        var claims = JwtClaimsSet.builder().issuer(properties.issuer())
                .audience(List.of(properties.audience())).subject(user.id().toString())
                .issuedAt(now).expiresAt(now.plusSeconds(properties.accessTokenSeconds()))
                .claim("roles", List.of(user.role().name())).build();
        var header = JwsHeader.with(SignatureAlgorithm.RS256).build();
        var token = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new TokenView(token, "Bearer", properties.accessTokenSeconds(), user);
    }
}
