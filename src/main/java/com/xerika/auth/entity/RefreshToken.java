package com.xerika.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
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

    @Column(unique = true, nullable = false)
    public String tokenHash;

    public LocalDateTime expiresAt;
    public boolean revoked;

    public LocalDateTime createdAt;
}