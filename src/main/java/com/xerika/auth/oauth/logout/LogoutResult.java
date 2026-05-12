package com.xerika.auth.oauth.logout;

import java.util.List;

public record LogoutResult(boolean terminated, List<String> frontchannelLogoutUris) {

    public static LogoutResult none() {
        return new LogoutResult(false, List.of());
    }
}
