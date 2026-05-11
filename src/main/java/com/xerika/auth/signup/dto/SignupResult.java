package com.xerika.auth.signup.dto;

public record SignupResult(
    boolean ok,
    String userId,
    String verificationToken,
    String error,
    String errorDescription
) {

    public static SignupResult success(String userId, String verificationToken) {
        return new SignupResult(true, userId, verificationToken, null, null);
    }

    public static SignupResult error(String error, String description) {
        return new SignupResult(false, null, null, error, description);
    }
}
