package com.xerika.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "user_sessions")
public class UserSession {

    @Id
    public UUID id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    public User user;

    @Column(unique = true, nullable = false)
    public String sessionToken;

    public String ipAddress;

    @Column(columnDefinition = "TEXT")
    public String userAgent;

    public LocalDateTime expiresAt;
    public LocalDateTime lastAccessedAt;
    public LocalDateTime createdAt;
}