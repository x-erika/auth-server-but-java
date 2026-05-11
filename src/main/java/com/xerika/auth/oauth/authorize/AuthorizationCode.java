package com.xerika.auth.oauth.authorize;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "auth_codes")
public class AuthorizationCode {

    @Id
    @Column(name = "code", nullable = false)
    public String code;

    @Column(name = "client_id", nullable = false)
    public String clientId;

    @Column(name = "user_id", nullable = false)
    public UUID userId;

    @Column(name = "session_id", nullable = false)
    public UUID sessionId;

    @Column(name = "redirect_uri", columnDefinition = "TEXT", nullable = false)
    public String redirectUri;

    @Column(name = "scope", columnDefinition = "TEXT")
    public String scope;

    @Column(name = "state", columnDefinition = "TEXT")
    public String state;

    @Column(name = "nonce", columnDefinition = "TEXT")
    public String nonce;

    @Column(name = "code_challenge", columnDefinition = "TEXT")
    public String codeChallenge;

    @Column(name = "code_challenge_method")
    public String codeChallengeMethod;

    @Column(name = "expires_at", nullable = false)
    public LocalDateTime expiresAt;

    @Column(name = "created_at")
    public LocalDateTime createdAt;
}
