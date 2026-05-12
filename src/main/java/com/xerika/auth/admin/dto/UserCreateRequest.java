package com.xerika.auth.admin.dto;

public record UserCreateRequest(
    String email,
    String username,
    String password,
    String firstName,
    String lastName,
    Boolean enabled,
    Boolean emailVerified
) {
}
