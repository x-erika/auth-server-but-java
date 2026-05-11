package com.xerika.auth.signup;

import com.xerika.auth.common.crypto.Argon2Hasher;
import com.xerika.auth.common.crypto.RandomTokens;
import com.xerika.auth.common.crypto.Sha256;
import com.xerika.auth.role.Role;
import com.xerika.auth.role.RoleRepository;
import com.xerika.auth.signup.dto.SignupRequest;
import com.xerika.auth.signup.dto.SignupResult;
import com.xerika.auth.signup.dto.VerifyEmailResult;
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
public class SignupFlow {

    private static final int VERIFICATION_TOKEN_TTL_HOURS = 24;
    private static final int VERIFICATION_TOKEN_BYTES = 32;

    @Inject
    UserRepository userRepository;

    @Inject
    CredentialRepository credentialRepository;

    @Inject
    RoleRepository roleRepository;

    @Inject
    EmailVerificationRepository emailVerificationRepository;

    @Transactional
    public SignupResult signup(SignupRequest req) {
        if (req == null) {
            return SignupResult.error("invalid_request", "request body required");
        }

        if (isBlank(req.email()) || isBlank(req.password()) || isBlank(req.username())) {
            return SignupResult.error("invalid_request", "email, password, username are required");
        }

        if (req.password().length() < 8) {
            return SignupResult.error("invalid_request", "password must be at least 8 characters");
        }

        if (userRepository.findByEmail(req.email()).isPresent()) {
            return SignupResult.error("conflict", "email already registered");
        }

        if (userRepository.findByUsername(req.username()).isPresent()) {
            return SignupResult.error("conflict", "username already taken");
        }

        User user = new User();
        user.id = UUID.randomUUID();
        user.email = req.email();
        user.emailVerified = false;
        user.username = req.username();
        user.firstName = req.firstName();
        user.lastName = req.lastName();
        user.enabled = true;
        user.createdAt = LocalDateTime.now();
        user.updatedAt = LocalDateTime.now();
        userRepository.persist(user);

        Map<String, String> argon2 = Argon2Hasher.hash(req.password());
        Credential credential = new Credential();
        credential.id = UUID.randomUUID();
        credential.user = user;
        credential.type = "password";
        credential.secretData = argon2.get("secretData");
        credential.credentialData = argon2.get("credentialData");
        credential.createdAt = LocalDateTime.now();
        credential.updatedAt = LocalDateTime.now();
        credentialRepository.persist(credential);

        roleRepository.findByName("user").ifPresent(role ->
            roleRepository.assignToUser(user.id, role.id)
        );

        String tokenRaw = RandomTokens.urlSafe(VERIFICATION_TOKEN_BYTES);
        String tokenHash = Sha256.base64Url(tokenRaw);

        EmailVerification verification = new EmailVerification();
        verification.id = UUID.randomUUID();
        verification.user = user;
        verification.tokenHash = tokenHash;
        verification.expiresAt = LocalDateTime.now().plusHours(VERIFICATION_TOKEN_TTL_HOURS);
        verification.createdAt = LocalDateTime.now();
        emailVerificationRepository.persist(verification);

        return SignupResult.success(user.id.toString(), tokenRaw);
    }

    @Transactional
    public VerifyEmailResult verifyEmail(String tokenRaw) {
        if (isBlank(tokenRaw)) {
            return VerifyEmailResult.error("invalid_request", "token is required");
        }

        String hash = Sha256.base64Url(tokenRaw);
        Optional<EmailVerification> verificationOpt = emailVerificationRepository.findByTokenHash(hash);
        if (verificationOpt.isEmpty()) {
            return VerifyEmailResult.error("invalid_token", "verification token not found");
        }

        EmailVerification verification = verificationOpt.get();

        if (verification.consumedAt != null) {
            return VerifyEmailResult.error("invalid_token", "verification token already used");
        }

        if (verification.expiresAt.isBefore(LocalDateTime.now())) {
            return VerifyEmailResult.error("invalid_token", "verification token expired");
        }

        verification.user.emailVerified = true;
        verification.consumedAt = LocalDateTime.now();

        return VerifyEmailResult.success(verification.user.id.toString());
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
