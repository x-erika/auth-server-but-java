package com.xerika.auth.oauth.consent;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class UserConsentRepository {

    @PersistenceContext
    EntityManager em;

    public Optional<UserConsent> findById(UUID id) {
        return Optional.ofNullable(em.find(UserConsent.class, id));
    }

    public List<UserConsent> findByUserId(UUID userId) {
        return em.createQuery(
                "SELECT c FROM UserConsent c WHERE c.userId = :userId ORDER BY c.grantedAt DESC",
                UserConsent.class
            )
            .setParameter("userId", userId)
            .getResultList();
    }

    @Transactional
    public int deleteById(UUID id) {
        return em.createQuery("DELETE FROM UserConsent c WHERE c.id = :id")
            .setParameter("id", id)
            .executeUpdate();
    }

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
