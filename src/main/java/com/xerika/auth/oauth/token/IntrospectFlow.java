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

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("active", true);
        Map<String, Object> claims = MAPPER.convertValue(claimsOpt.get(), new TypeReference<Map<String, Object>>() {});
        payload.putAll(claims);
        return IntrospectResult.success(payload);
    }

    private boolean authenticateClient(Client client, String clientSecret) {
        if (!"confidential".equalsIgnoreCase(client.type)) {
            return true;
        }
        return !isBlank(clientSecret) && clientSecret.equals(client.clientSecret);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
