package com.xerika.auth.session;

import com.xerika.auth.user.User;

import java.time.LocalDateTime;
import java.util.UUID;

public class SessionSnapshot {

    public UUID id;
    public UUID userId;
    public String userEmail;
    public String userUsername;
    public boolean userEmailVerified;
    public boolean userEnabled;
    public String ipAddress;
    public String userAgent;
    public LocalDateTime expiresAt;
    public LocalDateTime createdAt;

    public static SessionSnapshot from(UserSession s) {
        SessionSnapshot snap = new SessionSnapshot();
        snap.id = s.id;
        if (s.user != null) {
            snap.userId = s.user.id;
            snap.userEmail = s.user.email;
            snap.userUsername = s.user.username;
            snap.userEmailVerified = s.user.emailVerified;
            snap.userEnabled = s.user.enabled;
        }
        snap.ipAddress = s.ipAddress;
        snap.userAgent = s.userAgent;
        snap.expiresAt = s.expiresAt;
        snap.createdAt = s.createdAt;
        return snap;
    }

    public UserSession toEntity() {
        UserSession s = new UserSession();
        s.id = id;
        s.ipAddress = ipAddress;
        s.userAgent = userAgent;
        s.expiresAt = expiresAt;
        s.createdAt = createdAt;
        if (userId != null) {
            User u = new User();
            u.id = userId;
            u.email = userEmail;
            u.username = userUsername;
            u.emailVerified = userEmailVerified;
            u.enabled = userEnabled;
            s.user = u;
        }
        return s;
    }
}
