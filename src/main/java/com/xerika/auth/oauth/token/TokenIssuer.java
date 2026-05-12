package com.xerika.auth.oauth.token;

import com.xerika.auth.client.Client;
import com.xerika.auth.common.crypto.JwtSigner;
import com.xerika.auth.common.crypto.RandomTokens;
import com.xerika.auth.common.crypto.Sha256;
import com.xerika.auth.oauth.Scopes;
import com.xerika.auth.oauth.authorize.ClaimsRequest;
import com.xerika.auth.role.RoleRepository;
import com.xerika.auth.session.UserSession;
import com.xerika.auth.user.User;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@ApplicationScoped
public class TokenIssuer {

    private static final int REFRESH_TOKEN_TTL_DAYS = 30;

    @Inject
    RefreshTokenRepository refreshTokenRepository;

    @Inject
    JwtSigner jwtSigner;

    @Inject
    RoleRepository roleRepository;

    public Map<String, Object> issueForClient(Client client, String scope) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("scope", scope == null ? "" : scope);
        claims.put("client_id", client.clientId);

        String accessToken = jwtSigner.signAccessToken(
            client.clientId,
            client.clientId,
            claims
        );

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("token_type", "Bearer");
        response.put("expires_in", jwtSigner.accessTokenTtlSeconds());
        response.put("access_token", accessToken);
        response.put("scope", scope == null ? "" : scope);
        return response;
    }

    public Map<String, Object> issue(
        User user,
        Client client,
        UserSession session,
        String scope,
        String nonce,
        String claimsRequestedJson
    ) {
        List<String> roles = List.copyOf(roleRepository.findEffectiveNamesByUserId(user.id));
        Set<String> scopes = Scopes.parse(scope);
        ClaimsRequest claimsRequest = ClaimsRequest.parse(claimsRequestedJson);

        String accessToken = jwtSigner.signAccessToken(
            user.id.toString(),
            client.clientId,
            buildAccessTokenClaims(user, session, roles, scope, claimsRequest)
        );

        String refreshTokenRaw = RandomTokens.urlSafe(48);
        String refreshTokenHash = Sha256.base64Url(refreshTokenRaw);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.id = UUID.randomUUID();
        refreshToken.user = user;
        refreshToken.client = client;
        refreshToken.session = session;
        refreshToken.tokenHash = refreshTokenHash;
        refreshToken.revoked = false;
        refreshToken.createdAt = LocalDateTime.now();
        refreshToken.expiresAt = LocalDateTime.now().plusDays(REFRESH_TOKEN_TTL_DAYS);
        refreshTokenRepository.persist(refreshToken);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("token_type", "Bearer");
        response.put("expires_in", jwtSigner.accessTokenTtlSeconds());
        response.put("access_token", accessToken);
        response.put("refresh_token", refreshTokenRaw);
        response.put("scope", scope == null ? "" : scope);

        if (scopes.contains("openid")) {
            long authTime = session.createdAt.toEpochSecond(ZoneOffset.UTC);
            String idToken = jwtSigner.signIdToken(
                user.id.toString(),
                client.clientId,
                nonce,
                authTime,
                buildIdTokenClaims(user, scopes, claimsRequest)
            );
            response.put("id_token", idToken);
        }

        return response;
    }

    private Map<String, Object> buildAccessTokenClaims(
        User user,
        UserSession session,
        List<String> roles,
        String scope,
        ClaimsRequest claimsRequest
    ) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("email", user.email);
        claims.put("username", user.username);
        claims.put("sid", session.id.toString());
        claims.put("roles", roles);
        claims.put("scope", scope == null ? "" : scope);
        if (!claimsRequest.userinfoClaims().isEmpty()) {
            claims.put("claims_userinfo", List.copyOf(claimsRequest.userinfoClaims()));
        }
        return claims;
    }

    private Map<String, Object> buildIdTokenClaims(User user, Set<String> scopes, ClaimsRequest claimsRequest) {
        Map<String, Object> claims = new LinkedHashMap<>();

        boolean includeEmail = scopes.contains("email") || claimsRequest.idTokenClaims().contains("email");
        boolean includeEmailVerified = scopes.contains("email") || claimsRequest.idTokenClaims().contains("email_verified");
        boolean includeProfile = scopes.contains("profile");

        if (includeEmail) {
            claims.put("email", user.email);
        }
        if (includeEmailVerified) {
            claims.put("email_verified", user.emailVerified);
        }

        if (includeProfile || claimsRequest.idTokenClaims().contains("preferred_username")) {
            claims.put("preferred_username", user.username);
        }
        if (includeProfile || claimsRequest.idTokenClaims().contains("given_name")) {
            if (user.firstName != null) {
                claims.put("given_name", user.firstName);
            }
        }
        if (includeProfile || claimsRequest.idTokenClaims().contains("family_name")) {
            if (user.lastName != null) {
                claims.put("family_name", user.lastName);
            }
        }
        if (includeProfile || claimsRequest.idTokenClaims().contains("name")) {
            if (user.firstName != null && user.lastName != null) {
                claims.put("name", user.firstName + " " + user.lastName);
            }
        }

        return claims;
    }
}
