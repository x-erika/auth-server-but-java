package com.xerika.auth.oauth.authorize;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.time.LocalDateTime;

@ApplicationScoped
public class AuthCodeStore {

    @PersistenceContext
    EntityManager em;

    @Transactional
    public void put(AuthorizationCode code) {
        code.createdAt = LocalDateTime.now();
        em.persist(code);
    }

    @Transactional
    public AuthorizationCode consume(String code) {
        AuthorizationCode existing = em.find(AuthorizationCode.class, code);
        if (existing == null) {
            return null;
        }
        em.remove(existing);
        return existing;
    }

    @Transactional
    public void cleanupExpired() {
        em.createQuery("DELETE FROM AuthorizationCode a WHERE a.expiresAt < :now")
            .setParameter("now", LocalDateTime.now())
            .executeUpdate();
    }
}
