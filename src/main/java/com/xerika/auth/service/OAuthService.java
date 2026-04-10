package com.xerika.auth.service;

import com.xerika.auth.entity.Client;
import com.xerika.auth.entity.RefreshToken;
import com.xerika.auth.entity.User;
import com.xerika.auth.entity.UserSession;
import com.xerika.auth.repository.ClientRepository;
import com.xerika.auth.repository.RefreshTokenRepository;
import com.xerika.auth.repository.SessionRepository;
import com.xerika.auth.repository.UserRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@ApplicationScoped
public class OAuthService {

    private static final Map<String, AuthorizationCodeData> AUTH_CODES = new ConcurrentHashMap<>();
    private static final SecureRandom RANDOM = new SecureRandom();

    @Inject
    ClientRepository clientRepository;

    @Inject
    SessionService sessionService;

    @Inject
    SessionRepository sessionRepository;

    @Inject
    UserRepository userRepository;

    @Inject
    TokenService tokenService;

    @Inject
    RefreshTokenRepository refreshTokenRepository;

    public AuthorizeResult authorize(
        String sessionToken,
        String clientId,
        String redirectUri,
        String responseType,
        String scope,
        String state,
        String codeChallenge,
        String codeChallengeMethod
    ) {
        if (!"code".equals(responseType)) {
            return AuthorizeResult.error("unsupported_response_type", "Only response_type=code is supported");
        }

        if (clientId == null || clientId.isBlank() || redirectUri == null || redirectUri.isBlank()) {
            return AuthorizeResult.error("invalid_request", "client_id and redirect_uri are required");
        }

        UserSession session = sessionService.findActiveSession(sessionToken).orElse(null);
        if (session == null) {
            return AuthorizeResult.error("invalid_session", "Login required");
        }

        Client client = clientRepository.findByClientId(clientId).orElse(null);
        if (client == null || !client.enabled) {
            return AuthorizeResult.error("unauthorized_client", "Unknown or disabled client");
        }

        if (!clientRepository.isRedirectUriAllowed(client.id, redirectUri)) {
            return AuthorizeResult.error("invalid_request", "redirect_uri is not registered");
        }

        if (!isScopeAllowed(scope, client.scopes)) {
            return AuthorizeResult.error("invalid_scope", "Requested scope is not allowed for this client");
        }

        if (client.pkceRequired) {
            if (codeChallenge == null || codeChallenge.isBlank()) {
                return AuthorizeResult.error("invalid_request", "code_challenge is required");
            }

            String method = codeChallengeMethod == null || codeChallengeMethod.isBlank() ? "plain" : codeChallengeMethod;
            if (!Set.of("S256", "plain").contains(method)) {
                return AuthorizeResult.error("invalid_request", "Unsupported code_challenge_method");
            }
            codeChallengeMethod = method;
        }

        cleanupExpiredCodes();

        String code = randomToken(48);
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(3);

        AUTH_CODES.put(code, new AuthorizationCodeData(
            code,
            client.clientId,
            session.user.id,
            session.id,
            redirectUri,
            scope,
            state,
            codeChallenge,
            codeChallengeMethod,
            expiresAt
        ));

        String location = buildRedirect(redirectUri, Map.of(
            "code", code,
            "state", state == null ? "" : state
        ));

        return AuthorizeResult.success(URI.create(location));
    }

    public TokenResult token(
        String grantType,
        String code,
        String redirectUri,
        String clientId,
        String clientSecret,
        String codeVerifier,
        String refreshTokenRaw
    ) {
        if ("authorization_code".equals(grantType)) {
            return tokenFromAuthorizationCode(code, redirectUri, clientId, clientSecret, codeVerifier);
        }

        if ("refresh_token".equals(grantType)) {
            return tokenFromRefreshToken(refreshTokenRaw, clientId, clientSecret);
        }

        return TokenResult.error("unsupported_grant_type", "Supported: authorization_code, refresh_token");
    }

    private TokenResult tokenFromAuthorizationCode(
        String code,
        String redirectUri,
        String clientId,
        String clientSecret,
        String codeVerifier
    ) {
        if (isBlank(code) || isBlank(redirectUri) || isBlank(clientId)) {
            return TokenResult.error("invalid_request", "code, redirect_uri, client_id are required");
        }

        Client client = clientRepository.findByClientId(clientId).orElse(null);
        if (client == null || !client.enabled) {
            return TokenResult.error("unauthorized_client", "Unknown or disabled client");
        }

        if ("confidential".equalsIgnoreCase(client.type)) {
            if (isBlank(clientSecret) || !clientSecret.equals(client.clientSecret)) {
                return TokenResult.error("invalid_client", "Invalid client credentials");
            }
        }

        AuthorizationCodeData authCode = AUTH_CODES.remove(code);
        if (authCode == null) {
            return TokenResult.error("invalid_grant", "Invalid authorization code");
        }

        if (authCode.expiresAt().isBefore(LocalDateTime.now())) {
            return TokenResult.error("invalid_grant", "Authorization code expired");
        }

        if (!clientId.equals(authCode.clientId()) || !redirectUri.equals(authCode.redirectUri())) {
            return TokenResult.error("invalid_grant", "Code binding mismatch");
        }

        if (client.pkceRequired) {
            if (isBlank(codeVerifier)) {
                return TokenResult.error("invalid_request", "code_verifier is required");
            }
            if (!verifyPkce(codeVerifier, authCode.codeChallenge(), authCode.codeChallengeMethod())) {
                return TokenResult.error("invalid_grant", "PKCE verification failed");
            }
        }

        User user = userRepository.findById(authCode.userId()).orElse(null);
        UserSession session = sessionRepository.findById(authCode.sessionId()).orElse(null);
        if (user == null || session == null) {
            return TokenResult.error("invalid_grant", "User/session not found");
        }

        return issueTokens(user, client, session, authCode.scope());
    }

    private TokenResult tokenFromRefreshToken(String refreshTokenRaw, String clientId, String clientSecret) {
        if (isBlank(refreshTokenRaw) || isBlank(clientId)) {
            return TokenResult.error("invalid_request", "refresh_token and client_id are required");
        }

        Client client = clientRepository.findByClientId(clientId).orElse(null);
        if (client == null || !client.enabled) {
            return TokenResult.error("unauthorized_client", "Unknown or disabled client");
        }

        if ("confidential".equalsIgnoreCase(client.type)) {
            if (isBlank(clientSecret) || !clientSecret.equals(client.clientSecret)) {
                return TokenResult.error("invalid_client", "Invalid client credentials");
            }
        }

        String refreshTokenHash = sha256Base64Url(refreshTokenRaw);
        RefreshToken stored = refreshTokenRepository.findByTokenHash(refreshTokenHash).orElse(null);
        if (stored == null) {
            return TokenResult.error("invalid_grant", "Invalid refresh token");
        }

        if (stored.revoked || (stored.expiresAt != null && stored.expiresAt.isBefore(LocalDateTime.now()))) {
            return TokenResult.error("invalid_grant", "Refresh token is revoked or expired");
        }

        if (stored.client == null || !client.id.equals(stored.client.id)) {
            return TokenResult.error("invalid_grant", "Refresh token client mismatch");
        }

        User user = stored.user;
        UserSession session = stored.session;
        if (user == null || session == null || !user.enabled) {
            return TokenResult.error("invalid_grant", "User/session not valid");
        }

        // rotation: revoke old refresh token then issue a new pair
        stored.revoked = true;
        refreshTokenRepository.update(stored);

        return issueTokens(user, client, session, client.scopes);
    }

    private TokenResult issueTokens(User user, Client client, UserSession session, String scope) {
        String accessToken = tokenService.issueAccessToken(user);

        String refreshTokenRaw = randomToken(48);
        String refreshTokenHash = sha256Base64Url(refreshTokenRaw);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.id = UUID.randomUUID();
        refreshToken.user = user;
        refreshToken.client = client;
        refreshToken.session = session;
        refreshToken.tokenHash = refreshTokenHash;
        refreshToken.revoked = false;
        refreshToken.createdAt = LocalDateTime.now();
        refreshToken.expiresAt = LocalDateTime.now().plusDays(30);
        refreshTokenRepository.persist(refreshToken);

        return TokenResult.success(Map.of(
            "token_type", "Bearer",
            "expires_in", 900,
            "access_token", accessToken,
            "refresh_token", refreshTokenRaw,
            "scope", scope == null ? "" : scope
        ));
    }

    public RevokeResult revoke(String token, String tokenTypeHint, String clientId, String clientSecret) {
        if (isBlank(token) || isBlank(clientId)) {
            return RevokeResult.error("invalid_request", "token and client_id are required");
        }

        Client client = clientRepository.findByClientId(clientId).orElse(null);
        if (client == null || !client.enabled) {
            return RevokeResult.error("invalid_client", "Unknown or disabled client");
        }

        if ("confidential".equalsIgnoreCase(client.type)) {
            if (isBlank(clientSecret) || !clientSecret.equals(client.clientSecret)) {
                return RevokeResult.error("invalid_client", "Invalid client credentials");
            }
        }

        // Current implementation only supports refresh token revocation.
        if (tokenTypeHint != null && !tokenTypeHint.isBlank() && !"refresh_token".equals(tokenTypeHint)) {
            return RevokeResult.success();
        }

        String tokenHash = sha256Base64Url(token);
        RefreshToken stored = refreshTokenRepository.findByTokenHash(tokenHash).orElse(null);
        if (stored == null) {
            return RevokeResult.success();
        }

        if (stored.client == null || !client.id.equals(stored.client.id)) {
            return RevokeResult.success();
        }

        if (!stored.revoked) {
            stored.revoked = true;
            refreshTokenRepository.update(stored);
        }

        return RevokeResult.success();
    }

    private void cleanupExpiredCodes() {
        LocalDateTime now = LocalDateTime.now();
        AUTH_CODES.entrySet().removeIf(e -> e.getValue().expiresAt().isBefore(now));
    }

    private boolean isScopeAllowed(String requestedScope, String allowedScopesRaw) {
        if (requestedScope == null || requestedScope.isBlank()) {
            return true;
        }

        if (allowedScopesRaw == null || allowedScopesRaw.isBlank()) {
            return false;
        }

        Set<String> allowed = Arrays.stream(allowedScopesRaw.split("[\\s,]+"))
            .map(String::trim)
            .filter(s -> !s.isBlank())
            .collect(Collectors.toSet());

        return Arrays.stream(requestedScope.split("\\s+"))
            .map(String::trim)
            .filter(s -> !s.isBlank())
            .allMatch(allowed::contains);
    }

    private boolean verifyPkce(String codeVerifier, String codeChallenge, String method) {
        if (codeChallenge == null || method == null) {
            return false;
        }

        if ("plain".equalsIgnoreCase(method)) {
            return codeVerifier.equals(codeChallenge);
        }

        if ("S256".equalsIgnoreCase(method)) {
            return sha256Base64Url(codeVerifier).equals(codeChallenge);
        }

        return false;
    }

    private String buildRedirect(String baseUri, Map<String, String> params) {
        StringBuilder sb = new StringBuilder(baseUri);
        sb.append(baseUri.contains("?") ? "&" : "?");

        boolean first = true;
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (!first) {
                sb.append("&");
            }
            first = false;
            sb.append(urlEncode(e.getKey()))
                .append("=")
                .append(urlEncode(e.getValue() == null ? "" : e.getValue()));
        }

        return sb.toString();
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private String randomToken(int bytesLength) {
        byte[] bytes = new byte[bytesLength];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String sha256Base64Url(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    public record AuthorizeResult(boolean ok, URI redirect, String error, String errorDescription) {
        public static AuthorizeResult success(URI redirect) {
            return new AuthorizeResult(true, redirect, null, null);
        }

        public static AuthorizeResult error(String error, String description) {
            return new AuthorizeResult(false, null, error, description);
        }
    }

    public record TokenResult(boolean ok, Map<String, Object> payload, String error, String errorDescription) {
        public static TokenResult success(Map<String, Object> payload) {
            return new TokenResult(true, payload, null, null);
        }

        public static TokenResult error(String error, String description) {
            return new TokenResult(false, null, error, description);
        }
    }

    public record RevokeResult(boolean ok, String error, String errorDescription) {
        public static RevokeResult success() {
            return new RevokeResult(true, null, null);
        }

        public static RevokeResult error(String error, String description) {
            return new RevokeResult(false, error, description);
        }
    }

    public record AuthorizationCodeData(
        String code,
        String clientId,
        UUID userId,
        UUID sessionId,
        String redirectUri,
        String scope,
        String state,
        String codeChallenge,
        String codeChallengeMethod,
        LocalDateTime expiresAt
    ) {
    }
}
