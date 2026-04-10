package com.xerika.auth.service;

import com.xerika.auth.entity.Credential;
import com.xerika.auth.entity.User;
import com.xerika.auth.repository.CredentialRepository;
import com.xerika.auth.repository.UserRepository;
import com.xerika.auth.util.PasswordUtil;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.Optional;

@ApplicationScoped
public class AuthService {

    @Inject
    UserRepository userRepository;

    @Inject
    CredentialRepository credentialRepository;

    public Optional<User> authenticateByEmail(String email, String rawPassword) {
        if (email == null || email.isBlank() || rawPassword == null || rawPassword.isBlank()) {
            return Optional.empty();
        }

        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) {
            return Optional.empty();
        }

        User user = userOpt.get();
        if (!user.enabled || !user.emailVerified) {
            return Optional.empty();
        }

        Optional<Credential> credentialOpt = credentialRepository.findFirstByUserIdAndType(user.id, "password");
        if (credentialOpt.isEmpty()) {
            return Optional.empty();
        }

        Credential credential = credentialOpt.get();
        boolean ok = PasswordUtil.verifyArgon2(rawPassword, credential.secretData, credential.credentialData);
        return ok ? Optional.of(user) : Optional.empty();
    }
}
