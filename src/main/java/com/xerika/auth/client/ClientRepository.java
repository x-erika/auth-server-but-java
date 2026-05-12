package com.xerika.auth.client;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.List;
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

    public List<Client> findAll() {
        return em.createQuery("SELECT c FROM Client c ORDER BY c.clientId", Client.class)
            .getResultList();
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

    @Transactional
    public void persist(Client client) {
        em.persist(client);
    }

    @Transactional
    public Client update(Client client) {
        return em.merge(client);
    }

    @Transactional
    public void delete(UUID id) {
        Client existing = em.find(Client.class, id);
        if (existing != null) {
            em.remove(existing);
        }
    }

    @Transactional
    public void addRedirectUri(RedirectUri uri) {
        em.persist(uri);
    }

    @Transactional
    public int removeRedirectUri(UUID redirectUriId) {
        return em.createQuery("DELETE FROM RedirectUri r WHERE r.id = :id")
            .setParameter("id", redirectUriId)
            .executeUpdate();
    }
}
