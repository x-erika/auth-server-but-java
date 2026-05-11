package com.xerika.auth.oauth.authorize;

import java.net.URI;

public record AuthorizeResult(boolean ok, URI redirect, String error, String errorDescription) {

    public static AuthorizeResult success(URI redirect) {
        return new AuthorizeResult(true, redirect, null, null);
    }

    public static AuthorizeResult error(String error, String description) {
        return new AuthorizeResult(false, null, error, description);
    }
}
