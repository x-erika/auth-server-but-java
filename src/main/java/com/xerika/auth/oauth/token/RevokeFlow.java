package com.xerika.auth.oauth.token;

import com.xerika.auth.client.Client;
import com.xerika.auth.client.ClientRepository;
import com.xerika.auth.common.crypto.Sha256;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class RevokeFlow {

    @Inject
    ClientRepository clientRepository;

    @Inject
    RefreshTokenRepository refreshTokenRepository;

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

        if (tokenTypeHint != null && !tokenTypeHint.isBlank() && !"refresh_token".equals(tokenTypeHint)) {
            return RevokeResult.success();
        }

        String tokenHash = Sha256.base64Url(token);
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
        return !isBlank(clientSecret) && clientSecret.equals(client.clientSecret);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
