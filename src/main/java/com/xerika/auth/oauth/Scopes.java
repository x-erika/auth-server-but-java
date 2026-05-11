package com.xerika.auth.oauth;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public final class Scopes {

    private Scopes() {
    }

    public static Set<String> parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(raw.split("[\\s,]+"))
            .map(String::trim)
            .filter(s -> !s.isBlank())
            .collect(Collectors.toSet());
    }

    public static boolean isSubsetOf(String requested, String allowed) {
        if (requested == null || requested.isBlank()) {
            return true;
        }
        if (allowed == null || allowed.isBlank()) {
            return false;
        }
        Set<String> allowedSet = parse(allowed);
        return parse(requested).stream().allMatch(allowedSet::contains);
    }
}
