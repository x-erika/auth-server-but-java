package com.xerika.auth.service;

import com.xerika.auth.entity.User;
import com.xerika.auth.entity.UserSession;
import com.xerika.auth.repository.SessionRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class SessionService {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Inject
    SessionRepository sessionRepository;

    public UserSession createSession(User user, String ipAddress, String userAgent) {
        UserSession session = new UserSession();
        session.id = UUID.randomUUID();
        session.user = user;
        session.sessionToken = generateSessionToken();
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

    private String generateSessionToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
