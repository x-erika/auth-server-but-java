package com.xerika.auth.service;

import com.xerika.auth.entity.Credential;
import com.xerika.auth.entity.User;
import com.xerika.auth.repository.CredentialRepository;
import com.xerika.auth.repository.UserRepository;
import com.xerika.auth.util.PasswordUtil;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@ApplicationScoped
public class AdminBootstrapService {

    @Inject
    UserRepository userRepository;

    @Inject
    CredentialRepository credentialRepository;

    @Transactional
    void onStart(@Observes StartupEvent ev) {
        if (userRepository.findByEmail("admin@gmail.com").isPresent()) {
            return;
        }

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

        Map<String, String> argon2 = PasswordUtil.createArgon2Credential("admin123");

        Credential credential = new Credential();
        credential.id = UUID.randomUUID();
        credential.user = user;
        credential.type = "password";
        credential.secretData = argon2.get("secretData");
        credential.credentialData = argon2.get("credentialData");
        credential.createdAt = LocalDateTime.now();
        credential.updatedAt = LocalDateTime.now();
        credentialRepository.persist(credential);
    }
}
