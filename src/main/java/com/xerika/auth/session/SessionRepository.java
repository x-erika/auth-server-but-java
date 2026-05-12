package com.xerika.auth.session;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.time.LocalDateTime;
import java.util.List;
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

    public List<UserSession> findAllActive() {
        return em.createQuery(
                "SELECT s FROM UserSession s WHERE s.expiresAt IS NULL OR s.expiresAt > :now ORDER BY s.lastAccessedAt DESC",
                UserSession.class
            )
            .setParameter("now", LocalDateTime.now())
            .setMaxResults(200)
            .getResultList();
    }

    public List<UserSession> findActiveByUserId(UUID userId) {
        return em.createQuery(
                "SELECT s FROM UserSession s WHERE s.user.id = :userId AND (s.expiresAt IS NULL OR s.expiresAt > :now) ORDER BY s.lastAccessedAt DESC",
                UserSession.class
            )
            .setParameter("userId", userId)
            .setParameter("now", LocalDateTime.now())
            .getResultList();
    }

    @Transactional
    public int deleteById(UUID id) {
        return em.createQuery("DELETE FROM UserSession s WHERE s.id = :id")
            .setParameter("id", id)
            .executeUpdate();
    }

    @Transactional
    public int deleteAllByUserId(UUID userId) {
        return em.createQuery("DELETE FROM UserSession s WHERE s.user.id = :userId")
            .setParameter("userId", userId)
            .executeUpdate();
    }
}
