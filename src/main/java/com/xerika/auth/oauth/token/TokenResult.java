package com.xerika.auth.oauth.token;

import java.util.Map;

public record TokenResult(boolean ok, Map<String, Object> payload, String error, String errorDescription) {

    public static TokenResult success(Map<String, Object> payload) {
        return new TokenResult(true, payload, null, null);
    }

    public static TokenResult error(String error, String description) {
        return new TokenResult(false, null, error, description);
    }
}
