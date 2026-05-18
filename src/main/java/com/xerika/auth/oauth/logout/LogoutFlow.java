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
import org.jboss.logging.Logger;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class LogoutFlow {

    private static final Logger LOG = Logger.getLogger(LogoutFlow.class);

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

    public LogoutResult logout(String idTokenHint, String sessionToken, String postLogoutRedirectUri) {
        // Validate post_logout_redirect_uri against the requester client's registered
        // redirect URIs. Requires id_token_hint to identify the client (no spec-compliant
        // way to resolve client without it). Drops the redirect silently if not registered
        // — drop > error to avoid leaking which URIs are registered.
        // Trade-off: piggybacks on client.redirectUris (OAuth callback list) rather than
        // a dedicated post_logout_redirect_uris column. OIDC RP-Initiated Logout treats
        // them as separate sets; for this learning project we collapse them.
        String validatedPostLogoutRedirect = null;
        if (postLogoutRedirectUri != null && !postLogoutRedirectUri.isBlank()) {
            Client requester = resolveClientFromIdTokenHint(idTokenHint);
            if (requester != null
                && clientRepository.isRedirectUriAllowed(requester.id, postLogoutRedirectUri)) {
                validatedPostLogoutRedirect = postLogoutRedirectUri;
            } else {
                LOG.warnf("Dropped post_logout_redirect_uri '%s' — not registered or id_token_hint missing",
                    postLogoutRedirectUri);
            }
        }

        UUID sessionId = resolveSessionId(idTokenHint, sessionToken);
        if (sessionId == null) {
            return LogoutResult.none(validatedPostLogoutRedirect);
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

        return new LogoutResult(true, frontchannelUris, validatedPostLogoutRedirect);
    }

    private Client resolveClientFromIdTokenHint(String idTokenHint) {
        if (idTokenHint == null || idTokenHint.isBlank()) {
            return null;
        }
        Optional<JsonNode> claims = jwtValidator.validate(idTokenHint);
        if (claims.isEmpty()) {
            return null;
        }
        JsonNode aud = claims.get().get("aud");
        if (aud == null) {
            return null;
        }
        String clientId = aud.isArray() && !aud.isEmpty()
            ? aud.get(0).asText(null)
            : aud.asText(null);
        if (clientId == null || clientId.isBlank()) {
            return null;
        }
        return clientRepository.findByClientId(clientId).orElse(null);
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
