package com.xerika.auth.oauth.authorize;

import java.net.URI;

public record AuthorizeResult(
    boolean ok,
    URI redirect,
    String error,
    String errorDescription,
    String consentRequestId
) {

    public static AuthorizeResult success(URI redirect) {
        return new AuthorizeResult(true, redirect, null, null, null);
    }

    public static AuthorizeResult error(String error, String description) {
        return new AuthorizeResult(false, null, error, description, null);
    }

    public static AuthorizeResult consentRequired(String requestId) {
        return new AuthorizeResult(false, null, "consent_required", "User consent is required", requestId);
    }
}
