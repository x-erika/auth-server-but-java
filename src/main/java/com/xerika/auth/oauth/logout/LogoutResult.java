package com.xerika.auth.oauth.logout;

import java.util.List;

public record LogoutResult(
    boolean terminated,
    List<String> frontchannelLogoutUris,
    String validatedPostLogoutRedirectUri
) {

    public static LogoutResult none() {
        return new LogoutResult(false, List.of(), null);
    }

    public static LogoutResult none(String validatedPostLogoutRedirectUri) {
        return new LogoutResult(false, List.of(), validatedPostLogoutRedirectUri);
    }
}
