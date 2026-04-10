package com.xerika.auth.repository;

import com.xerika.auth.entity.UserSession;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class SessionRepository {

    @PersistenceContext
    EntityManager em;

    public Optional<UserSession> findById(UUID id) {
        return Optional.ofNullable(em.find(UserSession.class, id));
    }

    public Optional<UserSession> findByToken(String sessionToken) {
        return em.createQuery("SELECT s FROM UserSession s WHERE s.sessionToken = :token", UserSession.class)
            .setParameter("token", sessionToken)
            .getResultStream()
            .findFirst();
    }

    @Transactional
    public void persist(UserSession session) {
        em.persist(session);
    }

    @Transactional
    public void updateLastAccessed(UserSession session, LocalDateTime at) {
        UserSession managed = em.contains(session) ? session : em.merge(session);
        managed.lastAccessedAt = at;
    }

    @Transactional
    public void delete(UserSession session) {
        UserSession managed = em.contains(session) ? session : em.merge(session);
        em.remove(managed);
    }
}
