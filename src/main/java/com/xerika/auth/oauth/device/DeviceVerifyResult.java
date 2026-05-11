package com.xerika.auth.oauth.device;

public record DeviceVerifyResult(
    boolean ok,
    String error,
    String errorDescription
) {

    public static DeviceVerifyResult success() {
        return new DeviceVerifyResult(true, null, null);
    }

    public static DeviceVerifyResult error(String error, String description) {
        return new DeviceVerifyResult(false, error, description);
    }
}
