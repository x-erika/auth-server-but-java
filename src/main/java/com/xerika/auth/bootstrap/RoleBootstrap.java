package com.xerika.auth.bootstrap;

import com.xerika.auth.role.Role;
import com.xerika.auth.role.RoleRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.LocalDateTime;
import java.util.UUID;

@ApplicationScoped
public class RoleBootstrap {

    @Inject
    RoleRepository roleRepository;

    public void ensureCoreRoles() {
        ensureRole("admin", "Full administrative access");
        ensureRole("user", "Standard authenticated user");
    }

    private void ensureRole(String name, String description) {
        if (roleRepository.findByName(name).isPresent()) {
            return;
        }

        Role role = new Role();
        role.id = UUID.randomUUID();
        role.name = name;
        role.description = description;
        role.createdAt = LocalDateTime.now();
        roleRepository.persist(role);
    }
}
