package com.xerika.auth.bootstrap;

import com.xerika.auth.common.crypto.Argon2Hasher;
import com.xerika.auth.role.Role;
import com.xerika.auth.role.RoleRepository;
import com.xerika.auth.user.Credential;
import com.xerika.auth.user.CredentialRepository;
import com.xerika.auth.user.User;
import com.xerika.auth.user.UserRepository;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@ApplicationScoped
public class AdminBootstrap {

    @Inject
    RoleBootstrap roleBootstrap;

    @Inject
    UserRepository userRepository;

    @Inject
    CredentialRepository credentialRepository;

    @Inject
    RoleRepository roleRepository;

    @PersistenceContext
    EntityManager em;

    @Transactional
    void onStart(@Observes StartupEvent ev) {
        // Serialise concurrent startup on multi-replica deploys. Released at txn end.
        BootstrapLock.acquire(em);

        roleBootstrap.ensureCoreRoles();

        User user = userRepository.findByEmail("admin@gmail.com").orElseGet(this::createAdminUser);

        Role adminRole = roleRepository.findByName("admin")
            .orElseThrow(() -> new IllegalStateException("admin role missing after bootstrap"));

        if (!roleRepository.isAssigned(user.id, adminRole.id)) {
            roleRepository.assignToUser(user.id, adminRole.id);
            // assignToUser uses native SQL that bypasses JPA dirty-checking, so
            // the in-memory User.roles collection on `user` is now stale. Refresh
            // before any downstream code in this method could touch it.
            em.refresh(user);
        }
    }

    private User createAdminUser() {
        User user = new User();
        user.id = UUID.randomUUID();
        user.email = "admin@gmail.com";
        user.emailVerified = true;
        user.username = "admin";
        user.enabled = true;
        user.firstName = "Admin";
        user.lastName = "User";
        user.createdAt = LocalDateTime.now();
        user.updatedAt = LocalDateTime.now();
        userRepository.persist(user);

        Map<String, String> argon2 = Argon2Hasher.hash("admin123");

        Credential credential = new Credential();
        credential.id = UUID.randomUUID();
        credential.user = user;
        credential.type = "password";
        credential.secretData = argon2.get("secretData");
        credential.credentialData = argon2.get("credentialData");
        credential.createdAt = LocalDateTime.now();
        credential.updatedAt = LocalDateTime.now();
        credentialRepository.persist(credential);

        return user;
    }
}
