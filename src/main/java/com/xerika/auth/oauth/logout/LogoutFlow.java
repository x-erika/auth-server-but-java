package com.xerika.auth.oauth.logout;

import com.fasterxml.jackson.databind.JsonNode;
import com.xerika.auth.common.crypto.JwtValidator;
import com.xerika.auth.oauth.token.RefreshTokenRepository;
import com.xerika.auth.session.SessionRepository;
import com.xerika.auth.session.SessionService;
import com.xerika.auth.session.UserSession;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

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

    public boolean logout(String idTokenHint, String sessionToken) {
        UUID sessionId = resolveSessionId(idTokenHint, sessionToken);
        if (sessionId == null) {
            return false;
        }

        refreshTokenRepository.revokeBySessionId(sessionId);
        sessionRepository.findById(sessionId).ifPresent(sessionRepository::delete);
        return true;
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
