package com.spotix.authservice.core.ports;

import com.spotix.authservice.core.application.TokenView;
import com.spotix.authservice.core.application.UserView;

public interface TokenIssuer {
    TokenView issue(UserView user);
}
