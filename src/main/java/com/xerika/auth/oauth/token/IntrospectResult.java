package com.xerika.auth.oauth.token;

import java.util.Map;

public record IntrospectResult(boolean ok, Map<String, Object> payload, String error, String errorDescription) {

    public static IntrospectResult success(Map<String, Object> payload) {
        return new IntrospectResult(true, payload, null, null);
    }

    public static IntrospectResult error(String error, String description) {
        return new IntrospectResult(false, null, error, description);
    }
}
