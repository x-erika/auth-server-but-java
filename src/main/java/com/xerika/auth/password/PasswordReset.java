package com.xerika.auth.password;

import com.xerika.auth.user.User;
import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "password_resets")
public class PasswordReset {

    @Id
    @Column(name = "id", nullable = false)
    public UUID id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    public User user;

    @Column(name = "token_hash", unique = true, nullable = false, columnDefinition = "TEXT")
    public String tokenHash;

    @Column(name = "expires_at", nullable = false)
    public LocalDateTime expiresAt;

    @Column(name = "consumed_at")
    public LocalDateTime consumedAt;

    @Column(name = "created_at")
    public LocalDateTime createdAt;
}
