package com.xerika.auth.oauth.consent;

import jakarta.enterprise.context.ApplicationScoped;

import java.time.LocalDateTime;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@ApplicationScoped
public class PendingAuthorizationStore {

    private final Map<String, PendingAuthorization> store = new ConcurrentHashMap<>();

    public void put(PendingAuthorization pending) {
        store.put(pending.requestId, pending);
    }

    public Optional<PendingAuthorization> get(String requestId) {
        cleanupExpired();
        PendingAuthorization pending = requestId == null ? null : store.get(requestId);
        if (pending == null) {
            return Optional.empty();
        }
        if (pending.expiresAt != null && pending.expiresAt.isBefore(LocalDateTime.now())) {
            store.remove(requestId);
            return Optional.empty();
        }
        return Optional.of(pending);
    }

    public Optional<PendingAuthorization> take(String requestId) {
        Optional<PendingAuthorization> result = get(requestId);
        if (result.isPresent()) {
            store.remove(requestId);
        }
        return result;
    }

    private void cleanupExpired() {
        LocalDateTime now = LocalDateTime.now();
        Iterator<Map.Entry<String, PendingAuthorization>> it = store.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, PendingAuthorization> e = it.next();
            if (e.getValue().expiresAt != null && e.getValue().expiresAt.isBefore(now)) {
                it.remove();
            }
        }
    }
}
