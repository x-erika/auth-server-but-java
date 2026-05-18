package com.xerika.auth.oauth.authorize;

import java.time.LocalDateTime;
import java.util.UUID;

public class AuthorizationCode {

    public String code;
    public String clientId;
    public UUID userId;
    public UUID sessionId;
    public String redirectUri;
    public String scope;
    public String state;
    public String nonce;
    public String codeChallenge;
    public String codeChallengeMethod;
    public String claimsRequested;
    public LocalDateTime expiresAt;
    public LocalDateTime createdAt;
}
