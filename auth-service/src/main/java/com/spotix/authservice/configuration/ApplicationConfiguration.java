package com.spotix.authservice.configuration;

import com.spotix.authservice.core.application.*;
import com.spotix.authservice.core.ports.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.time.Clock;

@Configuration
public class ApplicationConfiguration {
    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    RegisterUserUseCase registerUserUseCase(UserStore users, PasswordHasher passwords, Clock clock) {
        return new RegisterUserUseCase(users, passwords, clock);
    }

    @Bean
    LoginUseCase loginUseCase(UserStore users, PasswordHasher passwords, TokenIssuer tokens) {
        return new LoginUseCase(users, passwords, tokens);
    }

    @Bean
    GetMeUseCase getMeUseCase(UserStore users) {
        return new GetMeUseCase(users);
    }
}
