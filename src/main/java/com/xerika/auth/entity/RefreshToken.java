package com.xerika.auth.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
    @Column(name = "id", nullable = false)
    public UUID id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    public User user;

    @ManyToOne
    @JoinColumn(name = "client_id", nullable = false)
    public Client client;

    @ManyToOne
    @JoinColumn(name = "session_id", nullable = false)
    public UserSession session;

    @Column(name = "token_hash", unique = true, nullable = false, columnDefinition = "TEXT")
    public String tokenHash;

    @Column(name = "expires_at")
    public LocalDateTime expiresAt;

    @Column(name = "revoked")
    public boolean revoked;

    @Column(name = "created_at")
    public LocalDateTime createdAt;
}
