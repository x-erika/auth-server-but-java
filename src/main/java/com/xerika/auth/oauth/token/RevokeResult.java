package com.xerika.auth.oauth.token;

public record RevokeResult(boolean ok, String error, String errorDescription) {

    public static RevokeResult success() {
        return new RevokeResult(true, null, null);
    }

    public static RevokeResult error(String error, String description) {
        return new RevokeResult(false, error, description);
    }
}
