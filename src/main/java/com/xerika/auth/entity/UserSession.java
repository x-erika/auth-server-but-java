package com.xerika.auth.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "user_sessions")
public class UserSession {

    @Id
    @Column(name = "id", nullable = false)
    public UUID id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    public User user;

    @Column(name = "session_token", unique = true, nullable = false, columnDefinition = "TEXT")
    public String sessionToken;

    @Column(name = "ip_address")
    public String ipAddress;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    public String userAgent;

    @Column(name = "expires_at")
    public LocalDateTime expiresAt;

    @Column(name = "last_accessed_at")
    public LocalDateTime lastAccessedAt;

    @Column(name = "created_at")
    public LocalDateTime createdAt;
}
