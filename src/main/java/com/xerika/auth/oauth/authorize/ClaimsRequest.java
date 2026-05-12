package com.xerika.auth.oauth.authorize;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

public final class ClaimsRequest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Set<String> idTokenClaims;
    private final Set<String> userinfoClaims;

    private ClaimsRequest(Set<String> idTokenClaims, Set<String> userinfoClaims) {
        this.idTokenClaims = idTokenClaims;
        this.userinfoClaims = userinfoClaims;
    }

    public static ClaimsRequest empty() {
        return new ClaimsRequest(Collections.emptySet(), Collections.emptySet());
    }

    public static ClaimsRequest parse(String json) {
        if (json == null || json.isBlank()) {
            return empty();
        }
        try {
            JsonNode node = MAPPER.readTree(json);
            return new ClaimsRequest(
                collectFieldNames(node, "id_token"),
                collectFieldNames(node, "userinfo")
            );
        } catch (Exception e) {
            return empty();
        }
    }

    private static Set<String> collectFieldNames(JsonNode root, String section) {
        Set<String> names = new LinkedHashSet<>();
        if (!root.has(section) || !root.get(section).isObject()) {
            return names;
        }
        JsonNode obj = root.get(section);
        Iterator<String> it = obj.fieldNames();
        while (it.hasNext()) {
            names.add(it.next());
        }
        return names;
    }

    public Set<String> idTokenClaims() {
        return idTokenClaims;
    }

    public Set<String> userinfoClaims() {
        return userinfoClaims;
    }

    public boolean isEmpty() {
        return idTokenClaims.isEmpty() && userinfoClaims.isEmpty();
    }
}
