package com.xerika.auth.oauth.consent;

import com.xerika.auth.oauth.Scopes;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.LocalDateTime;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

@ApplicationScoped
public class ConsentService {

    @Inject
    UserConsentRepository repository;

    public boolean hasConsent(UUID userId, UUID clientId, String requestedScopeRaw) {
        Set<String> requested = Scopes.parse(requestedScopeRaw);
        if (requested.isEmpty()) {
            return true;
        }
        UserConsent existing = repository.find(userId, clientId).orElse(null);
        if (existing == null) {
            return false;
        }
        Set<String> granted = Scopes.parse(existing.scopes);
        return granted.containsAll(requested);
    }

    public void grant(UUID userId, UUID clientId, String requestedScopeRaw) {
        Set<String> requested = Scopes.parse(requestedScopeRaw);

        UserConsent existing = repository.find(userId, clientId).orElse(null);
        if (existing == null) {
            UserConsent created = new UserConsent();
            created.id = UUID.randomUUID();
            created.userId = userId;
            created.clientId = clientId;
            created.scopes = String.join(" ", requested);
            created.grantedAt = LocalDateTime.now();
            created.updatedAt = LocalDateTime.now();
            repository.persist(created);
            return;
        }

        Set<String> merged = new LinkedHashSet<>(Scopes.parse(existing.scopes));
        merged.addAll(requested);
        existing.scopes = String.join(" ", merged);
        existing.updatedAt = LocalDateTime.now();
        repository.update(existing);
    }

    public void revoke(UUID userId, UUID clientId) {
        repository.revoke(userId, clientId);
    }
}
