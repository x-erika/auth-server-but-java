package com.xerika.auth.login;

import com.xerika.auth.common.crypto.Argon2Hasher;
import com.xerika.auth.user.Credential;
import com.xerika.auth.user.CredentialRepository;
import com.xerika.auth.user.User;
import com.xerika.auth.user.UserRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.Map;
import java.util.Optional;

@ApplicationScoped
public class LoginService {

    // Pre-computed dummy hash. Used to keep the Argon2 work-factor on every login
    // request, even when the user does not exist / has no credential — closes the
    // ~50ms timing oracle that let attackers enumerate registered+verified accounts
    // through response timing. Generated once at class load (~50ms blocking).
    private static final Map<String, String> DUMMY_HASH =
        Argon2Hasher.hash("dummy-not-a-real-password-timing-equalizer");

    @Inject
    UserRepository userRepository;

    @Inject
    CredentialRepository credentialRepository;

    public Optional<User> authenticateByEmail(String email, String rawPassword) {
        if (email == null || email.isBlank() || rawPassword == null || rawPassword.isBlank()) {
            return Optional.empty();
        }

        User user = userRepository.findByEmail(email).orElse(null);
        Credential credential = (user != null)
            ? credentialRepository.findFirstByUserIdAndType(user.id, "password").orElse(null)
            : null;

        String secretData = credential != null
            ? credential.secretData
            : DUMMY_HASH.get("secretData");
        String credentialData = credential != null
            ? credential.credentialData
            : DUMMY_HASH.get("credentialData");

        boolean ok = Argon2Hasher.verify(rawPassword, secretData, credentialData);

        if (user == null || !user.enabled || !user.emailVerified || credential == null || !ok) {
            return Optional.empty();
        }
        return Optional.of(user);
    }
}
