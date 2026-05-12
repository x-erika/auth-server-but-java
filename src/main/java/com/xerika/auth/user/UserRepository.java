package com.xerika.auth.user;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class UserRepository {

    @PersistenceContext
    EntityManager em;

    public Optional<User> findById(UUID id) {
        return Optional.ofNullable(em.find(User.class, id));
    }

    public Optional<User> findByEmail(String email) {
        return em.createQuery("SELECT u FROM User u WHERE u.email = :email", User.class)
            .setParameter("email", email)
            .getResultStream()
            .findFirst();
    }

    public Optional<User> findByUsername(String username) {
        return em.createQuery("SELECT u FROM User u WHERE u.username = :username", User.class)
            .setParameter("username", username)
            .getResultStream()
            .findFirst();
    }

    public List<User> findAll(int limit) {
        return em.createQuery("SELECT u FROM User u ORDER BY u.createdAt DESC", User.class)
            .setMaxResults(limit)
            .getResultList();
    }

    @Transactional
    public void persist(User user) {
        em.persist(user);
    }

    @Transactional
    public User update(User user) {
        return em.merge(user);
    }

    @Transactional
    public void delete(UUID id) {
        User existing = em.find(User.class, id);
        if (existing != null) {
            em.remove(existing);
        }
    }
}
