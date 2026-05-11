package com.xerika.auth.login.dto;

public record LoginResponse(String message, SessionPayload session, UserPayload user) {
}
