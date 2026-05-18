package com.xerika.auth.role;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
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

    public Set<String> findEffectiveNamesByUserId(UUID userId) {
        List<Role> directlyAssigned = em.createQuery(
                "SELECT r FROM Role r JOIN r.users u WHERE u.id = :userId",
                Role.class
            )
            .setParameter("userId", userId)
            .getResultList();

        Map<UUID, Role> rolesById = loadAllRolesById();
        Set<String> effective = new LinkedHashSet<>();
        for (Role assigned : directlyAssigned) {
            walkAncestors(assigned, rolesById, effective, new java.util.HashSet<>());
        }
        return effective;
    }

    private Map<UUID, Role> loadAllRolesById() {
        Map<UUID, Role> map = new HashMap<>();
        for (Role r : em.createQuery("SELECT r FROM Role r", Role.class).getResultList()) {
            map.put(r.id, r);
        }
        return map;
    }

    private void walkAncestors(Role role, Map<UUID, Role> all, Set<String> sink, Set<UUID> visited) {
        if (role == null || !visited.add(role.id)) {
            return;
        }
        sink.add(role.name);
        if (role.parentId != null) {
            walkAncestors(all.get(role.parentId), all, sink, visited);
        }
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

    /** Thrown when a setParent call would create a cycle in the role hierarchy. */
    public static class RoleCycleException extends RuntimeException {
        public RoleCycleException(String message) {
            super(message);
        }
    }

    @Transactional
    public void setParent(UUID childId, UUID parentId) {
        if (parentId != null) {
            if (childId.equals(parentId)) {
                throw new RoleCycleException("Role cannot be its own parent");
            }
            // Lock the roles table FOR UPDATE while reading the graph + writing the
            // new edge — two concurrent setParent calls can't both observe a
            // cycle-free graph and then both commit conflicting edges.
            if (wouldCreateCycleLocked(childId, parentId)) {
                throw new RoleCycleException("Cycle detected in role hierarchy");
            }
        }
        em.createQuery("UPDATE Role r SET r.parentId = :parentId WHERE r.id = :childId")
            .setParameter("parentId", parentId)
            .setParameter("childId", childId)
            .executeUpdate();
    }

    private boolean wouldCreateCycleLocked(UUID childId, UUID newParentId) {
        List<Role> all = em.createQuery("SELECT r FROM Role r", Role.class)
            .setLockMode(LockModeType.PESSIMISTIC_WRITE)
            .getResultList();
        Map<UUID, UUID> parentOf = new HashMap<>();
        for (Role r : all) {
            parentOf.put(r.id, r.parentId);
        }
        UUID cursor = newParentId;
        Set<UUID> seen = new HashSet<>();
        while (cursor != null) {
            if (cursor.equals(childId) || !seen.add(cursor)) {
                return true;
            }
            cursor = parentOf.get(cursor);
        }
        return false;
    }

    public List<Role> findAll() {
        return em.createQuery("SELECT r FROM Role r ORDER BY r.name", Role.class)
            .getResultList();
    }
}
