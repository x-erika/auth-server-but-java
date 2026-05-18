package com.xerika.auth.session;

import com.xerika.auth.common.crypto.Sha256;
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
import org.jboss.logging.Logger;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class SessionRepository {

    private static final Logger LOG = Logger.getLogger(SessionRepository.class);

    @PersistenceContext
    EntityManager em;

    @Inject
    RedisDataSource redis;

    @Inject
    RedisJson json;

    @Inject
    TransactionSynchronizationRegistry txReg;

    public Optional<UserSession> findById(UUID id) {
        return Optional.ofNullable(em.find(UserSession.class, id));
    }

    public Optional<UserSession> findByToken(String sessionToken) {
        if (sessionToken == null || sessionToken.isEmpty()) {
            return Optional.empty();
        }
        String tokenHash = Sha256.base64Url(sessionToken);
        Optional<UserSession> fromCache = readCache(tokenHash);
        if (fromCache.isPresent()) {
            return fromCache;
        }
        em.clear();
        Optional<UserSession> result = em.createQuery(
                "SELECT s FROM UserSession s WHERE s.sessionToken = :token",
                UserSession.class
            )
            .setParameter("token", sessionToken)
            .getResultStream()
            .findFirst();
        result.ifPresent(s -> populateCache(tokenHash, s));
        return result;
    }

    @Transactional
    public void persist(UserSession session) {
        em.persist(session);
        if (session.sessionToken == null || session.expiresAt == null) {
            return;
        }
        String tokenHash = Sha256.base64Url(session.sessionToken);
        long ttl = ttlFor(session.expiresAt);
        if (ttl <= 0) {
            return;
        }
        String payload = json.stringify(SessionSnapshot.from(session));
        populateAfterCommit(tokenHash, payload, ttl);
    }

    @Transactional
    public void updateLastAccessed(UserSession session, LocalDateTime at) {
        if (session == null || session.id == null) {
            return;
        }
        UserSession managed = em.find(UserSession.class, session.id);
        if (managed != null) {
            managed.lastAccessedAt = at;
        }
    }

    @Transactional
    public void delete(UserSession session) {
        if (session == null || session.id == null) {
            return;
        }
        UserSession managed = em.find(UserSession.class, session.id);
        if (managed == null) {
            return;
        }
        invalidateNowOrThrow(managed.sessionToken);
        em.remove(managed);
    }

    public List<UserSession> findAllActive() {
        return em.createQuery(
                "SELECT s FROM UserSession s WHERE s.expiresAt IS NULL OR s.expiresAt > :now ORDER BY s.lastAccessedAt DESC",
                UserSession.class
            )
            .setParameter("now", LocalDateTime.now())
            .setMaxResults(200)
            .getResultList();
    }

    public List<UserSession> findActiveByUserId(UUID userId) {
        return em.createQuery(
                "SELECT s FROM UserSession s WHERE s.user.id = :userId AND (s.expiresAt IS NULL OR s.expiresAt > :now) ORDER BY s.lastAccessedAt DESC",
                UserSession.class
            )
            .setParameter("userId", userId)
            .setParameter("now", LocalDateTime.now())
            .getResultList();
    }

    @Transactional
    public int deleteById(UUID id) {
        UserSession existing = em.find(UserSession.class, id);
        if (existing == null) {
            return 0;
        }
        invalidateNowOrThrow(existing.sessionToken);
        em.remove(existing);
        return 1;
    }

    public void invalidateCacheByUserId(UUID userId) {
        List<String> tokens = em.createQuery(
                "SELECT s.sessionToken FROM UserSession s WHERE s.user.id = :userId",
                String.class)
            .setParameter("userId", userId)
            .getResultList();
        for (String token : tokens) {
            if (token == null) {
                continue;
            }
            try {
                redis.execute("DEL", RedisKeys.session(Sha256.base64Url(token)));
            } catch (Exception e) {
                LOG.warnf(e, "Redis DEL failed during invalidateCacheByUserId(%s) — token cache will go stale until TTL",
                    userId);
            }
        }
    }

    @Transactional
    public int deleteAllByUserId(UUID userId) {
        List<String> tokens = em.createQuery(
                "SELECT s.sessionToken FROM UserSession s WHERE s.user.id = :userId",
                String.class)
            .setParameter("userId", userId)
            .getResultList();
        List<String> failedTokens = new ArrayList<>();
        for (String token : tokens) {
            if (token == null) {
                continue;
            }
            try {
                redis.execute("DEL", RedisKeys.session(Sha256.base64Url(token)));
            } catch (Exception e) {
                failedTokens.add(token);
            }
        }
        if (!failedTokens.isEmpty()) {
            LOG.errorf("Failed to DEL %d session keys from Redis during deleteAllByUserId(%s) — aborting Postgres delete",
                failedTokens.size(), userId);
            throw new RuntimeException("Bulk session invalidation: Redis unavailable");
        }
        return em.createQuery("DELETE FROM UserSession s WHERE s.user.id = :userId")
            .setParameter("userId", userId)
            .executeUpdate();
    }

    private void invalidateNowOrThrow(String sessionToken) {
        if (sessionToken == null) {
            return;
        }
        String tokenHash = Sha256.base64Url(sessionToken);
        try {
            redis.execute("DEL", RedisKeys.session(tokenHash));
        } catch (Exception e) {
            LOG.errorf(e, "DEL Redis failed during logout — aborting Postgres delete to avoid stale auth bypass");
            throw new RuntimeException("Logout failed: Redis unavailable", e);
        }
    }

    private Optional<UserSession> readCache(String tokenHash) {
        try {
            Response cached = redis.execute("GET", RedisKeys.session(tokenHash));
            if (cached == null) {
                return Optional.empty();
            }
            String raw = cached.toString();
            if (raw == null || raw.isEmpty()) {
                return Optional.empty();
            }
            SessionSnapshot snap = json.parse(raw, SessionSnapshot.class);
            return snap == null ? Optional.empty() : Optional.of(snap.toEntity());
        } catch (Exception e) {
            LOG.warnf(e, "Redis session cache read failed for tokenHash %s, falling back to Postgres", tokenHash);
            return Optional.empty();
        }
    }

    private void populateCache(String tokenHash, UserSession session) {
        long ttl = ttlFor(session.expiresAt);
        if (ttl <= 0) {
            return;
        }
        try {
            redis.execute("SET",
                RedisKeys.session(tokenHash),
                json.stringify(SessionSnapshot.from(session)),
                "EX", Long.toString(ttl));
        } catch (Exception e) {
            LOG.warnf(e, "Redis session cache populate failed for tokenHash %s", tokenHash);
        }
    }

    private void populateAfterCommit(String tokenHash, String payload, long ttl) {
        try {
            txReg.registerInterposedSynchronization(new Synchronization() {
                @Override
                public void beforeCompletion() {
                }

                @Override
                public void afterCompletion(int status) {
                    if (status == Status.STATUS_COMMITTED) {
                        try {
                            redis.execute("SET",
                                RedisKeys.session(tokenHash),
                                payload,
                                "EX", Long.toString(ttl));
                        } catch (Exception e) {
                            LOG.warnf(e, "Post-commit session cache populate failed for tokenHash %s", tokenHash);
                        }
                    }
                }
            });
        } catch (IllegalStateException e) {
            try {
                redis.execute("SET",
                    RedisKeys.session(tokenHash),
                    payload,
                    "EX", Long.toString(ttl));
            } catch (Exception inner) {
                LOG.warnf(inner, "Session cache populate failed (no active txn) for tokenHash %s", tokenHash);
            }
        }
    }

    private static long ttlFor(LocalDateTime expiresAt) {
        if (expiresAt == null) {
            return 0;
        }
        return Duration.between(LocalDateTime.now(), expiresAt).getSeconds();
    }
}
