package com.xerika.auth.login.dto;

public record LoginRequest(String identifier, String email, String password) {

    public String resolveIdentifier() {
        if (identifier != null && !identifier.isBlank()) {
            return identifier;
        }
        return email;
    }
}
