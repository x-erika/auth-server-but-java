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

    /**
     * RFC 6749 §4.1.2.1 error-redirect. The caller has already validated the
     * redirect URI against the client's registered list, so it's safe to bounce
     * the user-agent there with {@code error=...&error_description=...&state=...}.
     * Use {@link #error} for pre-validation failures (unknown client, unregistered
     * redirect_uri) so the redirect URI is never trusted unvalidated.
     */
    public static AuthorizeResult errorRedirect(URI redirect, String error, String description) {
        return new AuthorizeResult(false, redirect, error, description, null);
    }

    public static AuthorizeResult consentRequired(String requestId) {
        return new AuthorizeResult(false, null, "consent_required", "User consent is required", requestId);
    }
}
