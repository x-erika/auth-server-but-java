package com.xerika.auth.role;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class RoleRepository {

    @PersistenceContext
    EntityManager em;

    public Optional<Role> findByName(String name) {
        return em.createQuery("SELECT r FROM Role r WHERE r.name = :name", Role.class)
            .setParameter("name", name)
            .getResultStream()
            .findFirst();
    }

    public List<String> findNamesByUserId(UUID userId) {
        return em.createQuery(
                "SELECT r.name FROM Role r JOIN r.users u WHERE u.id = :userId",
                String.class
            )
            .setParameter("userId", userId)
            .getResultList();
    }

    public boolean isAssigned(UUID userId, UUID roleId) {
        Long count = em.createQuery(
                "SELECT COUNT(u) FROM User u JOIN u.roles r WHERE u.id = :userId AND r.id = :roleId",
                Long.class
            )
            .setParameter("userId", userId)
            .setParameter("roleId", roleId)
            .getSingleResult();
        return count != null && count > 0;
    }

    @Transactional
    public void persist(Role role) {
        em.persist(role);
    }

    @Transactional
    public void assignToUser(UUID userId, UUID roleId) {
        em.createNativeQuery("INSERT INTO user_roles (user_id, role_id) VALUES (?1, ?2)")
            .setParameter(1, userId)
            .setParameter(2, roleId)
            .executeUpdate();
    }

    @Transactional
    public int unassignFromUser(UUID userId, UUID roleId) {
        return em.createNativeQuery("DELETE FROM user_roles WHERE user_id = ?1 AND role_id = ?2")
            .setParameter(1, userId)
            .setParameter(2, roleId)
            .executeUpdate();
    }

    public List<Role> findAll() {
        return em.createQuery("SELECT r FROM Role r ORDER BY r.name", Role.class)
            .getResultList();
    }
}
