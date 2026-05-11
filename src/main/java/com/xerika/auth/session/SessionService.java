package com.xerika.auth.session;

import com.xerika.auth.common.crypto.RandomTokens;
import com.xerika.auth.user.User;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class SessionService {

    @Inject
    SessionRepository sessionRepository;

    public UserSession createSession(User user, String ipAddress, String userAgent) {
        UserSession session = new UserSession();
        session.id = UUID.randomUUID();
        session.user = user;
        session.sessionToken = RandomTokens.urlSafe(32);
        session.ipAddress = ipAddress;
        session.userAgent = userAgent;
        session.createdAt = LocalDateTime.now();
        session.lastAccessedAt = LocalDateTime.now();
        session.expiresAt = LocalDateTime.now().plusHours(8);

        sessionRepository.persist(session);
        return session;
    }

    public Optional<UserSession> findActiveSession(String sessionToken) {
        if (sessionToken == null || sessionToken.isBlank()) {
            return Optional.empty();
        }

        Optional<UserSession> sessionOpt = sessionRepository.findByToken(sessionToken);
        if (sessionOpt.isEmpty()) {
            return Optional.empty();
        }

        UserSession session = sessionOpt.get();
        if (session.expiresAt != null && session.expiresAt.isBefore(LocalDateTime.now())) {
            return Optional.empty();
        }

        if (session.user == null || !session.user.enabled) {
            return Optional.empty();
        }

        sessionRepository.updateLastAccessed(session, LocalDateTime.now());
        return Optional.of(session);
    }

    public boolean logout(String sessionToken) {
        Optional<UserSession> sessionOpt = findActiveSession(sessionToken);
        if (sessionOpt.isEmpty()) {
            return false;
        }

        sessionRepository.delete(sessionOpt.get());
        return true;
    }
}
