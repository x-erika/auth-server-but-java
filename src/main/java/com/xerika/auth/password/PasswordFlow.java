package com.xerika.auth.password;

import com.xerika.auth.common.crypto.Argon2Hasher;
import com.xerika.auth.common.crypto.RandomTokens;
import com.xerika.auth.common.crypto.Sha256;
import com.xerika.auth.session.SessionRepository;
import com.xerika.auth.user.Credential;
import com.xerika.auth.user.CredentialRepository;
import com.xerika.auth.user.User;
import com.xerika.auth.user.UserRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class PasswordFlow {

    private static final int RESET_TOKEN_TTL_MINUTES = 30;
    private static final int RESET_TOKEN_BYTES = 32;
    private static final int MIN_PASSWORD_LEN = 8;

    @Inject
    UserRepository userRepository;

    @Inject
    CredentialRepository credentialRepository;

    @Inject
    PasswordResetRepository passwordResetRepository;

    @Inject
    SessionRepository sessionRepository;

    /**
     * Issue a password reset token. Identifier can be email or username. To
     * prevent account enumeration via response shape/timing, the caller always
     * receives a "success" — but only existing accounts get a token in the
     * response. In production this token would be emailed, not returned.
     */
    @Transactional
    public Optional<String> requestReset(String identifier) {
        if (identifier == null || identifier.isBlank()) {
            return Optional.empty();
        }
        String trimmed = identifier.trim();
        User user = (trimmed.contains("@")
            ? userRepository.findByEmail(trimmed)
            : userRepository.findByUsername(trimmed).or(() -> userRepository.findByEmail(trimmed))
        ).orElse(null);
        if (user == null || !user.enabled) {
            return Optional.empty();
        }

        String tokenRaw = RandomTokens.urlSafe(RESET_TOKEN_BYTES);
        String tokenHash = Sha256.base64Url(tokenRaw);

        PasswordReset reset = new PasswordReset();
        reset.id = UUID.randomUUID();
        reset.user = user;
        reset.tokenHash = tokenHash;
        reset.expiresAt = LocalDateTime.now().plusMinutes(RESET_TOKEN_TTL_MINUTES);
        reset.createdAt = LocalDateTime.now();
        passwordResetRepository.persist(reset);

        return Optional.of(tokenRaw);
    }

    public enum ResetError { INVALID_TOKEN, WEAK_PASSWORD }

    @Transactional
    public Optional<ResetError> consumeReset(String tokenRaw, String newPassword) {
        if (newPassword == null || newPassword.length() < MIN_PASSWORD_LEN) {
            return Optional.of(ResetError.WEAK_PASSWORD);
        }
        if (tokenRaw == null || tokenRaw.isBlank()) {
            return Optional.of(ResetError.INVALID_TOKEN);
        }

        String hash = Sha256.base64Url(tokenRaw);
        PasswordReset reset = passwordResetRepository.findByTokenHash(hash).orElse(null);
        if (reset == null || reset.consumedAt != null
            || reset.expiresAt.isBefore(LocalDateTime.now())) {
            return Optional.of(ResetError.INVALID_TOKEN);
        }

        rotatePassword(reset.user, newPassword);
        reset.consumedAt = LocalDateTime.now();

        // Forces every other tab/device of this user to log in again with the
        // new password — defence against a thief who set up a reset and a
        // session in parallel.
        sessionRepository.deleteAllByUserId(reset.user.id);

        return Optional.empty();
    }

    public enum ChangeError { WRONG_PASSWORD, WEAK_PASSWORD }

    @Transactional
    public Optional<ChangeError> changePassword(UUID userId, String oldPassword, String newPassword) {
        if (newPassword == null || newPassword.length() < MIN_PASSWORD_LEN) {
            return Optional.of(ChangeError.WEAK_PASSWORD);
        }

        User user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            return Optional.of(ChangeError.WRONG_PASSWORD);
        }

        Credential credential = credentialRepository
            .findFirstByUserIdAndType(userId, "password")
            .orElse(null);
        if (credential == null) {
            return Optional.of(ChangeError.WRONG_PASSWORD);
        }

        boolean ok = oldPassword != null
            && Argon2Hasher.verify(oldPassword, credential.secretData, credential.credentialData);
        if (!ok) {
            return Optional.of(ChangeError.WRONG_PASSWORD);
        }

        rotatePassword(user, newPassword);
        return Optional.empty();
    }

    private void rotatePassword(User user, String newPassword) {
        Credential credential = credentialRepository
            .findFirstByUserIdAndType(user.id, "password")
            .orElse(null);

        Map<String, String> argon2 = Argon2Hasher.hash(newPassword);
        if (credential == null) {
            credential = new Credential();
            credential.id = UUID.randomUUID();
            credential.user = user;
            credential.type = "password";
            credential.createdAt = LocalDateTime.now();
        }
        credential.secretData = argon2.get("secretData");
        credential.credentialData = argon2.get("credentialData");
        credential.updatedAt = LocalDateTime.now();

        if (credential.id == null) {
            credentialRepository.persist(credential);
        } else {
            credentialRepository.update(credential);
        }
    }
}
