package com.xerika.auth.oauth.consent;

import com.xerika.auth.common.redis.RedisJson;
import com.xerika.auth.common.redis.RedisKeys;
import com.xerika.auth.common.redis.RedisLua;
import io.quarkus.redis.datasource.RedisDataSource;
import io.vertx.mutiny.redis.client.Response;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class PendingAuthorizationStore {

    @Inject
    RedisDataSource redis;

    @Inject
    RedisJson json;

    @Inject
    RedisLua lua;

    @ConfigProperty(name = "auth.redis.pending-auth.ttl-seconds", defaultValue = "600")
    long defaultTtlSeconds;

    public void put(PendingAuthorization pending) {
        if (pending == null || pending.requestId == null || pending.requestId.isEmpty()) {
            throw new IllegalArgumentException("PendingAuthorization.requestId is required");
        }
        long ttl = defaultTtlSeconds;
        if (pending.expiresAt != null) {
            long fromExpires = Duration.between(LocalDateTime.now(), pending.expiresAt).getSeconds();
            if (fromExpires > 0) {
                ttl = fromExpires;
            } else {
                return;
            }
        }
        String key = RedisKeys.pendingAuth(pending.requestId);
        redis.execute("SET", key, json.stringify(pending), "EX", Long.toString(ttl));
    }

    public Optional<PendingAuthorization> get(String requestId) {
        if (requestId == null || requestId.isEmpty()) {
            return Optional.empty();
        }
        Response r = redis.execute("GET", RedisKeys.pendingAuth(requestId));
        return decode(r);
    }

    public Optional<PendingAuthorization> take(String requestId) {
        if (requestId == null || requestId.isEmpty()) {
            return Optional.empty();
        }
        Response r = lua.eval(
            RedisLua.GET_AND_DEL,
            List.of(RedisKeys.pendingAuth(requestId)),
            List.of()
        );
        return decode(r);
    }

    private Optional<PendingAuthorization> decode(Response r) {
        if (r == null) {
            return Optional.empty();
        }
        String raw = r.toString();
        if (raw == null || raw.isEmpty()) {
            return Optional.empty();
        }
        PendingAuthorization p = json.parse(raw, PendingAuthorization.class);
        if (p == null) {
            return Optional.empty();
        }
        if (p.expiresAt != null && p.expiresAt.isBefore(LocalDateTime.now())) {
            return Optional.empty();
        }
        return Optional.of(p);
    }
}
