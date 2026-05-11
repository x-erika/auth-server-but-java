package com.xerika.auth.signup;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.Optional;

@ApplicationScoped
public class EmailVerificationRepository {

    @PersistenceContext
    EntityManager em;

    public Optional<EmailVerification> findByTokenHash(String tokenHash) {
        return em.createQuery("SELECT e FROM EmailVerification e WHERE e.tokenHash = :hash", EmailVerification.class)
            .setParameter("hash", tokenHash)
            .getResultStream()
            .findFirst();
    }

    @Transactional
    public void persist(EmailVerification verification) {
        em.persist(verification);
    }
}
