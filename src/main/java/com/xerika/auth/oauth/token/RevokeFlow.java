package com.xerika.auth.oauth.token;

import com.xerika.auth.client.Client;
import com.xerika.auth.client.ClientRepository;
import com.xerika.auth.common.crypto.HmacSha256;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class RevokeFlow {

    @Inject
    ClientRepository clientRepository;

    @Inject
    RefreshTokenRepository refreshTokenRepository;

    @Inject
    HmacSha256 hmac;

    public RevokeResult revoke(String token, String tokenTypeHint, String clientId, String clientSecret) {
        if (isBlank(token) || isBlank(clientId)) {
            return RevokeResult.error("invalid_request", "token and client_id are required");
        }

        Client client = clientRepository.findByClientId(clientId).orElse(null);
        if (client == null || !client.enabled) {
            return RevokeResult.error("invalid_client", "Unknown or disabled client");
        }

        if (!authenticateClient(client, clientSecret)) {
            return RevokeResult.error("invalid_client", "Invalid client credentials");
        }

        // RFC 7009 §2.1 — token_type_hint is just a hint. We currently only revoke
        // refresh tokens (access tokens are stateless JWTs that can't be revoked
        // server-side until expiry). Try the refresh-token table regardless of the
        // hint value; the hint at most lets future implementations skip a lookup.

        String tokenHash = hmac.compute(token);
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

    private boolean authenticateClient(Client client, String clientSecret) {
        if (!"confidential".equalsIgnoreCase(client.type)) {
            return true;
        }
        return !isBlank(clientSecret)
            && com.xerika.auth.client.ClientSecretHasher.verify(clientSecret, client.clientSecret);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
