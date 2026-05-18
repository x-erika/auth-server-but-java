package com.xerika.auth.oauth.token;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class RefreshTokenRepository {

    @PersistenceContext
    EntityManager em;

    public Optional<RefreshToken> findById(UUID id) {
        return Optional.ofNullable(em.find(RefreshToken.class, id));
    }

    public Optional<RefreshToken> findByTokenHash(String tokenHash) {
        return em.createQuery("SELECT r FROM RefreshToken r WHERE r.tokenHash = :tokenHash", RefreshToken.class)
            .setParameter("tokenHash", tokenHash)
            .getResultStream()
            .findFirst();
    }

    // Row-locking lookup for the refresh-rotation path. Must be called from inside
    // an enclosing @Transactional so the lock is held across the read/check/revoke
    // sequence. Translates to Postgres SELECT ... FOR UPDATE.
    public Optional<RefreshToken> findByTokenHashForUpdate(String tokenHash) {
        return em.createQuery("SELECT r FROM RefreshToken r WHERE r.tokenHash = :tokenHash", RefreshToken.class)
            .setParameter("tokenHash", tokenHash)
            .setLockMode(LockModeType.PESSIMISTIC_WRITE)
            .getResultStream()
            .findFirst();
    }

    @Transactional
    public void persist(RefreshToken refreshToken) {
        em.persist(refreshToken);
    }

    @Transactional
    public RefreshToken update(RefreshToken refreshToken) {
        return em.merge(refreshToken);
    }

    @Transactional
    public int revokeBySessionId(UUID sessionId) {
        return em.createQuery(
                "UPDATE RefreshToken r SET r.revoked = true " +
                "WHERE r.session.id = :sessionId AND r.revoked = false"
            )
            .setParameter("sessionId", sessionId)
            .executeUpdate();
    }

    public java.util.List<java.util.UUID> findClientIdsBySessionId(UUID sessionId) {
        return em.createQuery(
                "SELECT DISTINCT r.client.id FROM RefreshToken r WHERE r.session.id = :sessionId",
                java.util.UUID.class
            )
            .setParameter("sessionId", sessionId)
            .getResultList();
    }
}
