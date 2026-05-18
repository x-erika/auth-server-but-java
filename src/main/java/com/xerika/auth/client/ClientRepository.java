package com.xerika.auth.client;

import com.xerika.auth.common.redis.RedisJson;
import com.xerika.auth.common.redis.RedisKeys;
import io.quarkus.redis.datasource.RedisDataSource;
import io.vertx.mutiny.redis.client.Response;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Status;
import jakarta.transaction.Synchronization;
import jakarta.transaction.Transactional;
import jakarta.transaction.TransactionSynchronizationRegistry;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class ClientRepository {

    private static final Logger LOG = Logger.getLogger(ClientRepository.class);
    private static final SecureRandom JITTER = new SecureRandom();

    @PersistenceContext
    EntityManager em;

    @Inject
    RedisDataSource redis;

    @Inject
    RedisJson json;

    @Inject
    TransactionSynchronizationRegistry txReg;

    @ConfigProperty(name = "auth.redis.client-cache.ttl-seconds", defaultValue = "1800")
    long defaultTtlSeconds;

    public Optional<Client> findById(UUID id) {
        return Optional.ofNullable(em.find(Client.class, id));
    }

    public Optional<Client> findByClientId(String clientId) {
        if (clientId == null || clientId.isEmpty()) {
            return Optional.empty();
        }
        Optional<Client> fromCache = readCache(clientId);
        if (fromCache.isPresent()) {
            return fromCache;
        }
        em.clear();  // L1 may hold a stale Client from earlier in this request; query short-circuits to L1 by identity
        Optional<Client> result = em.createQuery(
                "SELECT DISTINCT c FROM Client c LEFT JOIN FETCH c.redirectUris WHERE c.clientId = :cid",
                Client.class
            )
            .setParameter("cid", clientId)
            .getResultStream()
            .findFirst();
        result.ifPresent(this::populateCache);
        return result;
    }

    public List<Client> findAll() {
        return em.createQuery("SELECT c FROM Client c ORDER BY c.clientId", Client.class)
            .getResultList();
    }

    public boolean isRedirectUriAllowed(UUID clientId, String redirectUri) {
        Long count = em.createQuery(
                "SELECT COUNT(r) FROM RedirectUri r WHERE r.client.id = :clientId AND r.uri = :uri",
                Long.class
            )
            .setParameter("clientId", clientId)
            .setParameter("uri", redirectUri)
            .getSingleResult();

        return count != null && count > 0;
    }

    @Transactional
    public void persist(Client client) {
        em.persist(client);
        invalidateAfterCommit(client.clientId);
    }

    @Transactional
    public Client update(Client client) {
        if (client.id == null) {
            throw new IllegalArgumentException("Client.id is required for update");
        }
        Client managed = em.find(Client.class, client.id);
        if (managed == null) {
            return null;
        }
        managed.clientSecret = client.clientSecret;
        managed.name = client.name;
        managed.type = client.type;
        managed.grantTypes = client.grantTypes;
        managed.responseTypes = client.responseTypes;
        managed.scopes = client.scopes;
        managed.pkceRequired = client.pkceRequired;
        managed.enabled = client.enabled;
        managed.baseUrl = client.baseUrl;
        managed.description = client.description;
        managed.accessTokenTtl = client.accessTokenTtl;
        managed.refreshTokenTtl = client.refreshTokenTtl;
        managed.frontchannelLogoutUri = client.frontchannelLogoutUri;
        managed.backchannelLogoutUri = client.backchannelLogoutUri;
        managed.updatedAt = client.updatedAt;
        invalidateAfterCommit(managed.clientId);
        return managed;
    }

    @Transactional
    public void delete(UUID id) {
        Client existing = em.find(Client.class, id);
        if (existing != null) {
            String cid = existing.clientId;
            em.remove(existing);
            invalidateAfterCommit(cid);
        }
    }

    @Transactional
    public void addRedirectUri(RedirectUri uri) {
        String invalidationClientId = uri.client == null ? null : uri.client.clientId;
        if (uri.client != null && uri.client.id != null && !em.contains(uri.client)) {
            uri.client = em.getReference(Client.class, uri.client.id);
        }
        em.persist(uri);
        if (invalidationClientId != null) {
            invalidateAfterCommit(invalidationClientId);
        }
    }

    @Transactional
    public int removeRedirectUri(UUID redirectUriId) {
        String owningClientId = em.createQuery(
                "SELECT r.client.clientId FROM RedirectUri r WHERE r.id = :id", String.class)
            .setParameter("id", redirectUriId)
            .getResultStream()
            .findFirst()
            .orElse(null);
        int n = em.createQuery("DELETE FROM RedirectUri r WHERE r.id = :id")
            .setParameter("id", redirectUriId)
            .executeUpdate();
        if (n > 0 && owningClientId != null) {
            invalidateAfterCommit(owningClientId);
        }
        return n;
    }

    public void invalidate(String clientId) {
        if (clientId == null || clientId.isEmpty()) {
            return;
        }
        try {
            redis.execute("DEL", RedisKeys.client(clientId));
        } catch (Exception e) {
            LOG.warnf(e, "Redis invalidate failed for client %s", clientId);
        }
    }

    private Optional<Client> readCache(String clientId) {
        try {
            Response cached = redis.execute("GET", RedisKeys.client(clientId));
            if (cached == null) {
                return Optional.empty();
            }
            String raw = cached.toString();
            if (raw == null || raw.isEmpty()) {
                return Optional.empty();
            }
            ClientSnapshot snap = json.parse(raw, ClientSnapshot.class);
            return snap == null ? Optional.empty() : Optional.of(snap.toEntity());
        } catch (Exception e) {
            LOG.warnf(e, "Redis cache read failed for client %s, falling back to Postgres", clientId);
            return Optional.empty();
        }
    }

    private void populateCache(Client client) {
        try {
            long ttl = jitteredTtl(defaultTtlSeconds);
            redis.execute("SET",
                RedisKeys.client(client.clientId),
                json.stringify(ClientSnapshot.from(client)),
                "EX", Long.toString(ttl));
        } catch (Exception e) {
            LOG.warnf(e, "Redis cache populate failed for client %s", client.clientId);
        }
    }

    private void invalidateAfterCommit(String clientId) {
        if (clientId == null || clientId.isEmpty()) {
            return;
        }
        try {
            txReg.registerInterposedSynchronization(new Synchronization() {
                @Override
                public void beforeCompletion() {
                }

                @Override
                public void afterCompletion(int status) {
                    if (status == Status.STATUS_COMMITTED) {
                        invalidate(clientId);
                    }
                }
            });
        } catch (IllegalStateException e) {
            invalidate(clientId);
        }
    }

    private static long jitteredTtl(long base) {
        double jitter = (JITTER.nextDouble() * 0.2) - 0.1;
        return Math.max(1, (long) (base * (1 + jitter)));
    }
}
