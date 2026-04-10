package com.xerika.auth.repository;

import com.xerika.auth.entity.Credential;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class CredentialRepository {

    @PersistenceContext
    EntityManager em;

    public Optional<Credential> findById(UUID id) {
        return Optional.ofNullable(em.find(Credential.class, id));
    }

    public List<Credential> findByUserId(UUID userId) {
        return em.createQuery("SELECT c FROM Credential c WHERE c.user.id = :userId", Credential.class)
            .setParameter("userId", userId)
            .getResultList();
    }

    public Optional<Credential> findFirstByUserIdAndType(UUID userId, String type) {
        return em.createQuery("SELECT c FROM Credential c WHERE c.user.id = :userId AND c.type = :type", Credential.class)
            .setParameter("userId", userId)
            .setParameter("type", type)
            .setMaxResults(1)
            .getResultStream()
            .findFirst();
    }

    @Transactional
    public void persist(Credential credential) {
        em.persist(credential);
    }
}
