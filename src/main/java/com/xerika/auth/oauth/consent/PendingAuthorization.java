package com.xerika.auth.oauth.consent;

import java.time.LocalDateTime;
import java.util.UUID;

public class PendingAuthorization {

    public String requestId;
    public UUID sessionId;
    public UUID userId;
    public String clientId;
    public String redirectUri;
    public String responseType;
    public String scope;
    public String state;
    public String nonce;
    public String prompt;
    public Long maxAge;
    public String codeChallenge;
    public String codeChallengeMethod;
    public String claimsRequested;
    public LocalDateTime expiresAt;
}
