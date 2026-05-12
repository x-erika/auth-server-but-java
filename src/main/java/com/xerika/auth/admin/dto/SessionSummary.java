package com.xerika.auth.admin.dto;

import com.xerika.auth.session.UserSession;

public record SessionSummary(
    String id,
    String userId,
    String username,
    String email,
    String ipAddress,
    String userAgent,
    String createdAt,
    String lastAccessedAt,
    String expiresAt
) {

    public static SessionSummary from(UserSession s) {
        return new SessionSummary(
            s.id.toString(),
            s.user == null ? null : s.user.id.toString(),
            s.user == null ? null : s.user.username,
            s.user == null ? null : s.user.email,
            s.ipAddress,
            s.userAgent,
            s.createdAt == null ? null : s.createdAt.toString(),
            s.lastAccessedAt == null ? null : s.lastAccessedAt.toString(),
            s.expiresAt == null ? null : s.expiresAt.toString()
        );
    }
}
