package com.spotix.authservice.core.application;

import com.spotix.authservice.core.domain.AuthException;
import com.spotix.authservice.core.ports.UserStore;
import java.util.UUID;

public class GetMeUseCase {
    private final UserStore users;

    public GetMeUseCase(UserStore users) {
        this.users = users;
    }

    public UserView execute(UUID actorId) {
        return users.findById(actorId).filter(u -> u.enabled()).map(UserView::from)
                .orElseThrow(() -> new AuthException(AuthException.Code.USER_UNAVAILABLE,
                        "User is unavailable"));
    }
}
