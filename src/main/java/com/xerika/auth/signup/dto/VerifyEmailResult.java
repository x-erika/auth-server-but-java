package com.xerika.auth.signup.dto;

public record VerifyEmailResult(
    boolean ok,
    String userId,
    String error,
    String errorDescription
) {

    public static VerifyEmailResult success(String userId) {
        return new VerifyEmailResult(true, userId, null, null);
    }

    public static VerifyEmailResult error(String error, String description) {
        return new VerifyEmailResult(false, null, error, description);
    }
}
