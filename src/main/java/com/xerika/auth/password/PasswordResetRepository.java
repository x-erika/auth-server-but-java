package com.xerika.auth.password;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.Optional;

@ApplicationScoped
public class PasswordResetRepository {

    @PersistenceContext
    EntityManager em;

    public Optional<PasswordReset> findByTokenHash(String tokenHash) {
        return em.createQuery(
                "SELECT p FROM PasswordReset p WHERE p.tokenHash = :hash", PasswordReset.class)
            .setParameter("hash", tokenHash)
            .getResultStream()
            .findFirst();
    }

    @Transactional
    public void persist(PasswordReset entity) {
        em.persist(entity);
    }

    /**
     * Mark every still-active reset token for this user as consumed, except the
     * one identified by {@code keepId} (which the caller is about to consume
     * itself). Defends against the case where a user requested multiple resets
     * — once one is used, the rest should not remain available for replay.
     */
    @Transactional
    public int consumeSiblingTokens(java.util.UUID userId, java.util.UUID keepId) {
        return em.createQuery(
                "UPDATE PasswordReset p SET p.consumedAt = :now "
                    + "WHERE p.user.id = :userId AND p.id <> :keepId AND p.consumedAt IS NULL"
            )
            .setParameter("now", java.time.LocalDateTime.now())
            .setParameter("userId", userId)
            .setParameter("keepId", keepId)
            .executeUpdate();
    }
}
