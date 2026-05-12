package com.xerika.auth.oauth.logout;

import com.fasterxml.jackson.databind.JsonNode;
import com.xerika.auth.client.Client;
import com.xerika.auth.client.ClientRepository;
import com.xerika.auth.common.crypto.JwtValidator;
import com.xerika.auth.oauth.token.RefreshTokenRepository;
import com.xerika.auth.session.SessionRepository;
import com.xerika.auth.session.SessionService;
import com.xerika.auth.session.UserSession;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class LogoutFlow {

    @Inject
    JwtValidator jwtValidator;

    @Inject
    SessionRepository sessionRepository;

    @Inject
    SessionService sessionService;

    @Inject
    RefreshTokenRepository refreshTokenRepository;

    @Inject
    ClientRepository clientRepository;

    @Inject
    BackchannelLogoutNotifier backchannelLogoutNotifier;

    @ConfigProperty(name = "auth.issuer.url", defaultValue = "http://localhost:8080")
    String issuerUrl;

    public LogoutResult logout(String idTokenHint, String sessionToken) {
        UUID sessionId = resolveSessionId(idTokenHint, sessionToken);
        if (sessionId == null) {
            return LogoutResult.none();
        }

        UUID userId = sessionRepository.findById(sessionId)
            .map(s -> s.user.id)
            .orElse(null);

        List<UUID> clientIds = refreshTokenRepository.findClientIdsBySessionId(sessionId);
        List<Client> involvedClients = new ArrayList<>();
        for (UUID id : clientIds) {
            clientRepository.findById(id).ifPresent(involvedClients::add);
        }

        refreshTokenRepository.revokeBySessionId(sessionId);
        sessionRepository.findById(sessionId).ifPresent(sessionRepository::delete);

        List<String> frontchannelUris = new ArrayList<>();
        for (Client client : involvedClients) {
            if (client.frontchannelLogoutUri != null && !client.frontchannelLogoutUri.isBlank()) {
                frontchannelUris.add(buildFrontchannelUrl(client.frontchannelLogoutUri, sessionId));
            }
            if (client.backchannelLogoutUri != null && !client.backchannelLogoutUri.isBlank()) {
                backchannelLogoutNotifier.notifyClient(client, userId, sessionId);
            }
        }

        return new LogoutResult(true, frontchannelUris);
    }

    private String buildFrontchannelUrl(String uri, UUID sessionId) {
        String sep = uri.contains("?") ? "&" : "?";
        return uri + sep
            + "iss=" + URLEncoder.encode(issuerUrl, StandardCharsets.UTF_8)
            + "&sid=" + URLEncoder.encode(sessionId.toString(), StandardCharsets.UTF_8);
    }

    private UUID resolveSessionId(String idTokenHint, String sessionToken) {
        if (idTokenHint != null && !idTokenHint.isBlank()) {
            Optional<JsonNode> claims = jwtValidator.validate(idTokenHint);
            if (claims.isPresent() && claims.get().has("sid")) {
                try {
                    return UUID.fromString(claims.get().get("sid").asText());
                } catch (IllegalArgumentException ignored) {
                }
            }
        }

        if (sessionToken != null && !sessionToken.isBlank()) {
            Optional<UserSession> session = sessionService.findActiveSession(sessionToken);
            if (session.isPresent()) {
                return session.get().id;
            }
        }

        return null;
    }
}
