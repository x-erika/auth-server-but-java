package com.xerika.auth.oauth.token;

import com.xerika.auth.client.Client;
import com.xerika.auth.client.ClientRepository;
import com.xerika.auth.common.crypto.HmacSha256;
import com.xerika.auth.oauth.Scopes;
import com.xerika.auth.oauth.authorize.AuthCodeStore;
import com.xerika.auth.oauth.authorize.AuthorizationCode;
import com.xerika.auth.oauth.device.DeviceAuthorization;
import com.xerika.auth.oauth.device.DeviceAuthorizationRepository;
import com.xerika.auth.oauth.pkce.PkceVerifier;
import com.xerika.auth.session.SessionRepository;
import com.xerika.auth.session.UserSession;
import com.xerika.auth.user.User;
import com.xerika.auth.user.UserRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import java.time.LocalDateTime;

@ApplicationScoped
public class TokenFlow {

    @Inject
    ClientRepository clientRepository;

    @Inject
    UserRepository userRepository;

    @Inject
    SessionRepository sessionRepository;

    @Inject
    AuthCodeStore authCodeStore;

    @Inject
    PkceVerifier pkceVerifier;

    @Inject
    RefreshTokenRepository refreshTokenRepository;

    @Inject
    TokenIssuer tokenIssuer;

    @Inject
    HmacSha256 hmac;

    @Inject
    DeviceAuthorizationRepository deviceRepository;

    // @Transactional so the refresh-rotation path (fromRefreshToken) can hold the
    // PESSIMISTIC_WRITE lock + revoke + persist new token atomically. Other grant
    // types only need read-or-single-write semantics, so the wrapper is harmless.
    @Transactional
    public TokenResult token(
        String grantType,
        String code,
        String redirectUri,
        String clientId,
        String clientSecret,
        String codeVerifier,
        String refreshTokenRaw,
        String scope,
        String deviceCode
    ) {
        if ("authorization_code".equals(grantType)) {
            return fromAuthorizationCode(code, redirectUri, clientId, clientSecret, codeVerifier);
        }

        if ("refresh_token".equals(grantType)) {
            return fromRefreshToken(refreshTokenRaw, clientId, clientSecret);
        }

        if ("client_credentials".equals(grantType)) {
            return fromClientCredentials(clientId, clientSecret, scope);
        }

        if ("urn:ietf:params:oauth:grant-type:device_code".equals(grantType)) {
            return fromDeviceCode(deviceCode, clientId, clientSecret);
        }

        return TokenResult.error(
            "unsupported_grant_type",
            "Supported: authorization_code, refresh_token, client_credentials, device_code"
        );
    }

    private TokenResult fromDeviceCode(String deviceCode, String clientId, String clientSecret) {
        if (isBlank(deviceCode) || isBlank(clientId)) {
            return TokenResult.error("invalid_request", "device_code and client_id are required");
        }

        Client client = clientRepository.findByClientId(clientId).orElse(null);
        if (client == null || !client.enabled) {
            return TokenResult.error("unauthorized_client", "Unknown or disabled client");
        }

        if (!authenticateClient(client, clientSecret)) {
            return TokenResult.error("invalid_client", "Invalid client credentials");
        }

        DeviceAuthorization auth = deviceRepository.findByDeviceCode(deviceCode).orElse(null);
        if (auth == null) {
            return TokenResult.error("invalid_grant", "Unknown device_code");
        }

        if (!clientId.equals(auth.clientId)) {
            return TokenResult.error("invalid_grant", "device_code does not belong to this client");
        }

        if (auth.expiresAt.isBefore(LocalDateTime.now())) {
            return TokenResult.error("expired_token", "device_code expired");
        }

        switch (auth.status) {
            case DeviceAuthorization.STATUS_PENDING:
                return TokenResult.error("authorization_pending", "User has not yet approved");
            case DeviceAuthorization.STATUS_DENIED:
                return TokenResult.error("access_denied", "User denied the authorization request");
            case DeviceAuthorization.STATUS_CONSUMED:
                return TokenResult.error("invalid_grant", "device_code already used");
            case DeviceAuthorization.STATUS_APPROVED:
                break;
            default:
                return TokenResult.error("invalid_grant", "Unknown device_code state");
        }

        if (auth.userId == null || auth.sessionId == null) {
            return TokenResult.error("invalid_grant", "Approved device_code missing user binding");
        }
        User user = userRepository.findById(auth.userId).orElse(null);
        UserSession session = sessionRepository.findById(auth.sessionId).orElse(null);
        if (user == null || session == null) {
            return TokenResult.error("invalid_grant", "User/session not found");
        }

        auth.status = DeviceAuthorization.STATUS_CONSUMED;
        deviceRepository.update(auth);

        return TokenResult.success(tokenIssuer.issue(user, client, session, auth.scope, null, null));
    }

    private TokenResult fromClientCredentials(String clientId, String clientSecret, String scope) {
        if (isBlank(clientId)) {
            return TokenResult.error("invalid_request", "client_id is required");
        }

        Client client = clientRepository.findByClientId(clientId).orElse(null);
        if (client == null || !client.enabled) {
            return TokenResult.error("unauthorized_client", "Unknown or disabled client");
        }

        if (!"confidential".equalsIgnoreCase(client.type)) {
            return TokenResult.error(
                "unauthorized_client",
                "client_credentials grant requires a confidential client"
            );
        }

        if (!authenticateClient(client, clientSecret)) {
            return TokenResult.error("invalid_client", "Invalid client credentials");
        }

        if (!Scopes.isSubsetOf(scope, client.scopes)) {
            return TokenResult.error("invalid_scope", "Requested scope is not allowed for this client");
        }

        return TokenResult.success(tokenIssuer.issueForClient(client, scope));
    }

    private TokenResult fromAuthorizationCode(
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

        if (!authenticateClient(client, clientSecret)) {
            return TokenResult.error("invalid_client", "Invalid client credentials");
        }

        AuthorizationCode authCode = authCodeStore.consume(code);
        if (authCode == null) {
            return TokenResult.error("invalid_grant", "Invalid authorization code");
        }

        if (authCode.expiresAt.isBefore(LocalDateTime.now())) {
            return TokenResult.error("invalid_grant", "Authorization code expired");
        }

        if (!clientId.equals(authCode.clientId) || !redirectUri.equals(authCode.redirectUri)) {
            return TokenResult.error("invalid_grant", "Code binding mismatch");
        }

        // Verify PKCE whenever the auth code carries a challenge, even if the client doesn't
        // require it. Prevents the downgrade where a client opted into PKCE at /authorize but
        // the server skipped verification here.
        boolean codeHasChallenge = authCode.codeChallenge != null && !authCode.codeChallenge.isBlank();
        if (client.pkceRequired || codeHasChallenge) {
            if (isBlank(codeVerifier)) {
                return TokenResult.error("invalid_request", "code_verifier is required");
            }
            if (!pkceVerifier.verify(codeVerifier, authCode.codeChallenge, authCode.codeChallengeMethod)) {
                return TokenResult.error("invalid_grant", "PKCE verification failed");
            }
        }

        User user = userRepository.findById(authCode.userId).orElse(null);
        UserSession session = sessionRepository.findById(authCode.sessionId).orElse(null);
        if (user == null || session == null) {
            return TokenResult.error("invalid_grant", "User/session not found");
        }

        return TokenResult.success(tokenIssuer.issue(
            user, client, session, authCode.scope, authCode.nonce, authCode.claimsRequested));
    }

    private TokenResult fromRefreshToken(String refreshTokenRaw, String clientId, String clientSecret) {
        if (isBlank(refreshTokenRaw) || isBlank(clientId)) {
            return TokenResult.error("invalid_request", "refresh_token and client_id are required");
        }

        Client client = clientRepository.findByClientId(clientId).orElse(null);
        if (client == null || !client.enabled) {
            return TokenResult.error("unauthorized_client", "Unknown or disabled client");
        }

        if (!authenticateClient(client, clientSecret)) {
            return TokenResult.error("invalid_client", "Invalid client credentials");
        }

        String refreshTokenHash = hmac.compute(refreshTokenRaw);
        // Row-lock for the read-check-revoke window. Without this, two parallel
        // refreshes with the same raw token could both observe revoked=false and
        // both succeed (token-family fork).
        RefreshToken stored = refreshTokenRepository.findByTokenHashForUpdate(refreshTokenHash).orElse(null);
        if (stored == null) {
            return TokenResult.error("invalid_grant", "Invalid refresh token");
        }

        // Reuse detection (OAuth 2.0 Security BCP §4.13): a presented-but-revoked
        // refresh token means either replay or compromise — kill the whole family.
        if (stored.revoked) {
            if (stored.session != null) {
                refreshTokenRepository.revokeBySessionId(stored.session.id);
            }
            return TokenResult.error("invalid_grant", "Refresh token revoked — session terminated");
        }

        if (stored.expiresAt != null && stored.expiresAt.isBefore(LocalDateTime.now())) {
            return TokenResult.error("invalid_grant", "Refresh token expired");
        }

        if (stored.client == null || !client.id.equals(stored.client.id)) {
            return TokenResult.error("invalid_grant", "Refresh token client mismatch");
        }

        User user = stored.user;
        UserSession session = stored.session;
        if (user == null || session == null || !user.enabled) {
            return TokenResult.error("invalid_grant", "User/session not valid");
        }

        stored.revoked = true;
        // Managed entity dirty-checks; explicit update kept for clarity. Runs in the
        // same @Transactional as tokenIssuer.issue's persist below so both commit or
        // roll back together.
        refreshTokenRepository.update(stored);

        return TokenResult.success(tokenIssuer.issue(user, client, session, client.scopes, null, null));
    }

    private boolean authenticateClient(Client client, String clientSecret) {
        if (!"confidential".equalsIgnoreCase(client.type)) {
            return true;
        }
        // Argon2-verified (constant-time inside MessageDigest.isEqual) with a
        // legacy plaintext fallback for not-yet-migrated rows.
        return !isBlank(clientSecret)
            && com.xerika.auth.client.ClientSecretHasher.verify(clientSecret, client.clientSecret);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
