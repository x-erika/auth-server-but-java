package com.xerika.auth.oauth.authorize;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xerika.auth.client.Client;
import jakarta.enterprise.context.ApplicationScoped;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

@ApplicationScoped
public class RequestObjectParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public Optional<JsonNode> parse(String requestJwt, Client client) {
        if (requestJwt == null || requestJwt.isBlank()) {
            return Optional.empty();
        }

        String[] parts = requestJwt.split("\\.");
        if (parts.length != 2 && parts.length != 3) {
            return Optional.empty();
        }

        try {
            JsonNode header = MAPPER.readTree(Base64.getUrlDecoder().decode(parts[0]));
            JsonNode payload = MAPPER.readTree(Base64.getUrlDecoder().decode(parts[1]));
            String alg = header.has("alg") ? header.get("alg").asText() : null;

            // alg=none is rejected outright — a request object can override
            // redirect_uri / scope / code_challenge, so an unsigned blob from a
            // public client is enough to defeat PKCE binding. Only HS256 with the
            // client's registered secret is accepted.
            if (!"HS256".equalsIgnoreCase(alg)) {
                return Optional.empty();
            }
            if (parts.length != 3 || client.clientSecret == null || client.clientSecret.isBlank()) {
                return Optional.empty();
            }
            if (!verifyHs256(parts[0] + "." + parts[1], parts[2], client.clientSecret)) {
                return Optional.empty();
            }
            return Optional.of(payload);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private boolean verifyHs256(String signingInput, String signatureB64, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] expected = mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
        byte[] provided = Base64.getUrlDecoder().decode(signatureB64);
        if (expected.length != provided.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < expected.length; i++) {
            diff |= expected[i] ^ provided[i];
        }
        return diff == 0;
    }
}
