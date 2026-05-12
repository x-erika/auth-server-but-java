package com.xerika.auth.admin.dto;

public record UserUpdateRequest(
    String firstName,
    String lastName,
    Boolean enabled,
    Boolean emailVerified,
    String newPassword
) {
}
