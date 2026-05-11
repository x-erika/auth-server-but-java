package com.xerika.auth.oauth.token;

import com.xerika.auth.client.Client;
import com.xerika.auth.client.ClientRepository;
import com.xerika.auth.common.crypto.Sha256;
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
    DeviceAuthorizationRepository deviceRepository;

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

        User user = auth.user;
        UserSession session = auth.session;
        if (user == null || session == null) {
            return TokenResult.error("invalid_grant", "Approved device_code missing user binding");
        }

        auth.status = DeviceAuthorization.STATUS_CONSUMED;
        deviceRepository.update(auth);

        return TokenResult.success(tokenIssuer.issue(user, client, session, auth.scope, null));
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

        if (client.pkceRequired) {
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

        return TokenResult.success(tokenIssuer.issue(user, client, session, authCode.scope, authCode.nonce));
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

        String refreshTokenHash = Sha256.base64Url(refreshTokenRaw);
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

        stored.revoked = true;
        refreshTokenRepository.update(stored);

        return TokenResult.success(tokenIssuer.issue(user, client, session, client.scopes, null));
    }

    private boolean authenticateClient(Client client, String clientSecret) {
        if (!"confidential".equalsIgnoreCase(client.type)) {
            return true;
        }
        return !isBlank(clientSecret) && clientSecret.equals(client.clientSecret);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
