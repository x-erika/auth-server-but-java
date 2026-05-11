package com.xerika.auth.login;

import com.xerika.auth.common.crypto.Argon2Hasher;
import com.xerika.auth.user.Credential;
import com.xerika.auth.user.CredentialRepository;
import com.xerika.auth.user.User;
import com.xerika.auth.user.UserRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.Optional;

@ApplicationScoped
public class LoginService {

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
        boolean ok = Argon2Hasher.verify(rawPassword, credential.secretData, credential.credentialData);
        return ok ? Optional.of(user) : Optional.empty();
    }
}
