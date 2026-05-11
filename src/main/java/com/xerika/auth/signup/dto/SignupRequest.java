package com.xerika.auth.signup.dto;

public record SignupRequest(
    String email,
    String password,
    String username,
    String firstName,
    String lastName
) {
}
