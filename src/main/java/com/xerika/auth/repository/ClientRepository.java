package com.xerika.auth.repository;

import com.xerika.auth.entity.Client;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class ClientRepository {

    @PersistenceContext
    EntityManager em;

    public Optional<Client> findById(UUID id) {
        return Optional.ofNullable(em.find(Client.class, id));
    }

    public Optional<Client> findByClientId(String clientId) {
        return em.createQuery("SELECT c FROM Client c WHERE c.clientId = :clientId", Client.class)
            .setParameter("clientId", clientId)
            .getResultStream()
            .findFirst();
    }

    public boolean isRedirectUriAllowed(UUID clientId, String redirectUri) {
        Long count = em.createQuery(
                "SELECT COUNT(r) FROM RedirectUri r WHERE r.client.id = :clientId AND r.uri = :uri",
                Long.class
            )
            .setParameter("clientId", clientId)
            .setParameter("uri", redirectUri)
            .getSingleResult();

        return count != null && count > 0;
    }
}
