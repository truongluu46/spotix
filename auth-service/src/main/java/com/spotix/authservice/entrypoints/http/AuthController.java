package com.spotix.authservice.entrypoints.http;

import com.spotix.authservice.core.application.*;
import com.spotix.authservice.entrypoints.http.dto.*;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import java.net.URI;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final RegisterUserUseCase register;
    private final LoginUseCase login;
    private final GetMeUseCase me;

    public AuthController(RegisterUserUseCase register, LoginUseCase login, GetMeUseCase me) {
        this.register = register;
        this.login = login;
        this.me = me;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        var user = register.execute(request.email(), request.password(), request.displayName());
        return ResponseEntity.created(URI.create("/api/auth/me")).body(UserResponse.from(user));
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        return LoginResponse.from(login.execute(request.email(), request.password()));
    }

    @GetMapping("/me")
    public UserResponse me(@AuthenticationPrincipal Jwt jwt) {
        return UserResponse.from(me.execute(UUID.fromString(jwt.getSubject())));
    }
}
