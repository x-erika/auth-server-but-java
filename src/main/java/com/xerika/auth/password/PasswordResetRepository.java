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
}
