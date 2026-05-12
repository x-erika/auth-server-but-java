package com.xerika.auth.oauth.consent;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class UserConsentRepository {

    @PersistenceContext
    EntityManager em;

    public Optional<UserConsent> find(UUID userId, UUID clientId) {
        return em.createQuery(
                "SELECT c FROM UserConsent c WHERE c.userId = :userId AND c.clientId = :clientId",
                UserConsent.class
            )
            .setParameter("userId", userId)
            .setParameter("clientId", clientId)
            .getResultStream()
            .findFirst();
    }

    @Transactional
    public void persist(UserConsent consent) {
        em.persist(consent);
    }

    @Transactional
    public void update(UserConsent consent) {
        em.merge(consent);
    }

    @Transactional
    public int revoke(UUID userId, UUID clientId) {
        return em.createQuery(
                "DELETE FROM UserConsent c WHERE c.userId = :userId AND c.clientId = :clientId"
            )
            .setParameter("userId", userId)
            .setParameter("clientId", clientId)
            .executeUpdate();
    }
}
