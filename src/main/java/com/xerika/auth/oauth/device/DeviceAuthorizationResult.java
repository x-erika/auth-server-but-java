package com.xerika.auth.oauth.device;

import java.util.Map;

public record DeviceAuthorizationResult(
    boolean ok,
    Map<String, Object> payload,
    String error,
    String errorDescription
) {

    public static DeviceAuthorizationResult success(Map<String, Object> payload) {
        return new DeviceAuthorizationResult(true, payload, null, null);
    }

    public static DeviceAuthorizationResult error(String error, String description) {
        return new DeviceAuthorizationResult(false, null, error, description);
    }
}
