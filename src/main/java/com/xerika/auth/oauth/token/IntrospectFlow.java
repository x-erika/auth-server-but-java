package com.xerika.auth.oauth.token;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xerika.auth.client.Client;
import com.xerika.auth.client.ClientRepository;
import com.xerika.auth.common.crypto.JwtValidator;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@ApplicationScoped
public class IntrospectFlow {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Inject
    ClientRepository clientRepository;

    @Inject
    JwtValidator jwtValidator;

    public IntrospectResult introspect(String token, String clientId, String clientSecret) {
        if (isBlank(token) || isBlank(clientId)) {
            return IntrospectResult.error("invalid_request", "token and client_id are required");
        }

        Client client = clientRepository.findByClientId(clientId).orElse(null);
        if (client == null || !client.enabled) {
            return IntrospectResult.error("invalid_client", "Unknown or disabled client");
        }

        if (!authenticateClient(client, clientSecret)) {
            return IntrospectResult.error("invalid_client", "Invalid client credentials");
        }

        Optional<JsonNode> claimsOpt = jwtValidator.validate(token);
        if (claimsOpt.isEmpty()) {
            return IntrospectResult.success(Map.of("active", false));
        }

        // Bind introspection to the calling client. RFC 7662 lets each resource
        // server introspect "its own" tokens; without this check, Client A could
        // POST Client B's access_token and read every claim — email, roles, sid.
        // We return the spec-correct "active: false" instead of an error so a
        // malicious caller can't distinguish "token doesn't belong to you" from
        // "token doesn't exist".
        JsonNode aud = claimsOpt.get().get("aud");
        if (!audienceMatches(aud, client.clientId)) {
            return IntrospectResult.success(Map.of("active", false));
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("active", true);
        Map<String, Object> claims = MAPPER.convertValue(claimsOpt.get(), new TypeReference<Map<String, Object>>() {});
        payload.putAll(claims);
        return IntrospectResult.success(payload);
    }

    private static boolean audienceMatches(JsonNode aud, String expected) {
        if (aud == null || aud.isNull()) {
            return false;
        }
        if (aud.isTextual()) {
            return expected.equals(aud.asText());
        }
        if (aud.isArray()) {
            for (JsonNode v : aud) {
                if (v.isTextual() && expected.equals(v.asText())) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean authenticateClient(Client client, String clientSecret) {
        if (!"confidential".equalsIgnoreCase(client.type)) {
            return true;
        }
        return !isBlank(clientSecret)
            && com.xerika.auth.client.ClientSecretHasher.verify(clientSecret, client.clientSecret);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
