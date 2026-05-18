package com.xerika.auth.oauth.device;

import com.xerika.auth.client.Client;
import com.xerika.auth.client.ClientRepository;
import com.xerika.auth.common.crypto.RandomTokens;
import com.xerika.auth.oauth.Scopes;
import com.xerika.auth.session.SessionService;
import com.xerika.auth.session.UserSession;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class DeviceFlow {

    private static final int DEVICE_CODE_TTL_SECONDS = 300;
    private static final int POLL_INTERVAL_SECONDS = 5;
    private static final char[] USER_CODE_ALPHABET =
        "BCDFGHJKLMNPQRSTVWXZ23456789".toCharArray();
    private static final SecureRandom RANDOM = new SecureRandom();

    @Inject
    ClientRepository clientRepository;

    @Inject
    SessionService sessionService;

    @Inject
    DeviceAuthorizationRepository deviceRepository;

    @ConfigProperty(name = "auth.issuer.url", defaultValue = "http://localhost:8080")
    String issuerUrl;

    public DeviceAuthorizationResult requestDeviceAuthorization(String clientId, String scope) {
        if (clientId == null || clientId.isBlank()) {
            return DeviceAuthorizationResult.error("invalid_request", "client_id is required");
        }

        Client client = clientRepository.findByClientId(clientId).orElse(null);
        if (client == null || !client.enabled) {
            return DeviceAuthorizationResult.error("unauthorized_client", "Unknown or disabled client");
        }

        if (!Scopes.isSubsetOf(scope, client.scopes)) {
            return DeviceAuthorizationResult.error("invalid_scope", "Requested scope is not allowed for this client");
        }

        deviceRepository.deleteExpired();

        DeviceAuthorization auth = new DeviceAuthorization();
        auth.id = UUID.randomUUID();
        auth.deviceCode = RandomTokens.urlSafe(32);
        auth.userCode = generateUserCode();
        auth.clientId = client.clientId;
        auth.scope = scope;
        auth.status = DeviceAuthorization.STATUS_PENDING;
        auth.expiresAt = LocalDateTime.now().plusSeconds(DEVICE_CODE_TTL_SECONDS);
        auth.createdAt = LocalDateTime.now();
        deviceRepository.persist(auth);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("device_code", auth.deviceCode);
        payload.put("user_code", auth.userCode);
        payload.put("verification_uri", issuerUrl + "/oauth/device");
        payload.put("verification_uri_complete",
            issuerUrl + "/oauth/device?user_code=" + auth.userCode);
        payload.put("expires_in", DEVICE_CODE_TTL_SECONDS);
        payload.put("interval", POLL_INTERVAL_SECONDS);

        return DeviceAuthorizationResult.success(payload);
    }

    public DeviceVerifyResult verifyUserCode(String userCode, String sessionToken, boolean approve) {
        if (userCode == null || userCode.isBlank()) {
            return DeviceVerifyResult.error("invalid_request", "user_code is required");
        }

        Optional<UserSession> sessionOpt = sessionService.findActiveSession(sessionToken);
        if (sessionOpt.isEmpty()) {
            return DeviceVerifyResult.error("invalid_session", "Login required");
        }

        DeviceAuthorization auth = deviceRepository.findByUserCode(userCode.trim()).orElse(null);
        if (auth == null) {
            return DeviceVerifyResult.error("invalid_user_code", "Unknown user_code");
        }

        if (auth.expiresAt.isBefore(LocalDateTime.now())) {
            return DeviceVerifyResult.error("expired_token", "user_code expired");
        }

        if (!DeviceAuthorization.STATUS_PENDING.equals(auth.status)) {
            return DeviceVerifyResult.error("invalid_user_code", "Already resolved");
        }

        UserSession session = sessionOpt.get();
        if (approve) {
            auth.status = DeviceAuthorization.STATUS_APPROVED;
            auth.userId = session.user.id;
            auth.sessionId = session.id;
        } else {
            auth.status = DeviceAuthorization.STATUS_DENIED;
        }
        deviceRepository.update(auth);

        return DeviceVerifyResult.success();
    }

    private String generateUserCode() {
        StringBuilder sb = new StringBuilder(9);
        for (int i = 0; i < 8; i++) {
            if (i == 4) {
                sb.append('-');
            }
            sb.append(USER_CODE_ALPHABET[RANDOM.nextInt(USER_CODE_ALPHABET.length)]);
        }
        return sb.toString();
    }
}
