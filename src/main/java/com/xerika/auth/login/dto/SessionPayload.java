package com.xerika.auth.login.dto;

import com.xerika.auth.session.UserSession;

public record SessionPayload(String sessionToken, String expiresAt, String lastAccessedAt) {

    public static SessionPayload from(UserSession session) {
        return new SessionPayload(
            session.sessionToken,
            session.expiresAt == null ? null : session.expiresAt.toString(),
            session.lastAccessedAt == null ? null : session.lastAccessedAt.toString()
        );
    }
}
