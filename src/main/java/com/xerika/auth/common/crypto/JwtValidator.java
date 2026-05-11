package com.xerika.auth.common.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

@ApplicationScoped
public class JwtValidator {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Inject
    RsaKeyProvider keys;

    @ConfigProperty(name = "auth.issuer.url", defaultValue = "http://localhost:8080")
    String expectedIssuer;

    public Optional<JsonNode> validate(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return Optional.empty();
        }

        try {
            byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(keys.publicKey());
            signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
            if (!signature.verify(signatureBytes)) {
                return Optional.empty();
            }

            JsonNode payload = MAPPER.readTree(Base64.getUrlDecoder().decode(parts[1]));

            long now = Instant.now().getEpochSecond();
            if (payload.has("exp") && payload.get("exp").asLong() < now) {
                return Optional.empty();
            }

            if (payload.has("nbf") && payload.get("nbf").asLong() > now) {
                return Optional.empty();
            }

            if (payload.has("iss") && !expectedIssuer.equals(payload.get("iss").asText())) {
                return Optional.empty();
            }

            return Optional.of(payload);
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
