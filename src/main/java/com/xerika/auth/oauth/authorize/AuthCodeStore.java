package com.xerika.auth.oauth.authorize;

import com.xerika.auth.common.crypto.Sha256;
import com.xerika.auth.common.redis.RedisJson;
import com.xerika.auth.common.redis.RedisKeys;
import com.xerika.auth.common.redis.RedisLua;
import io.quarkus.redis.datasource.RedisDataSource;
import io.vertx.mutiny.redis.client.Response;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;

@ApplicationScoped
public class AuthCodeStore {

    @Inject
    RedisDataSource redis;

    @Inject
    RedisJson json;

    @Inject
    RedisLua lua;

    public void put(AuthorizationCode code) {
        if (code.expiresAt == null) {
            throw new IllegalArgumentException("AuthorizationCode.expiresAt is required");
        }
        long ttlSeconds = Duration.between(LocalDateTime.now(), code.expiresAt).getSeconds();
        if (ttlSeconds <= 0) {
            return;
        }
        code.createdAt = LocalDateTime.now();
        // Hash the raw code before using it as a Redis key. A Redis dump or
        // KEYS-style scan would otherwise expose live authorization codes
        // verbatim; storing the hash means an attacker who reads the keystore
        // still needs the raw code (delivered only via redirect) to redeem.
        String key = RedisKeys.authCode(Sha256.base64Url(code.code));
        String payload = json.stringify(code);
        redis.execute("SET", key, payload, "NX", "EX", Long.toString(ttlSeconds));
    }

    public AuthorizationCode consume(String code) {
        if (code == null || code.isEmpty()) {
            return null;
        }
        String key = RedisKeys.authCode(Sha256.base64Url(code));
        Response r = lua.eval(RedisLua.GET_AND_DEL, List.of(key), List.of());
        if (r == null) {
            return null;
        }
        String raw = r.toString();
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        AuthorizationCode existing = json.parse(raw, AuthorizationCode.class);
        if (existing == null) {
            return null;
        }
        if (existing.expiresAt != null && existing.expiresAt.isBefore(LocalDateTime.now())) {
            return null;
        }
        return existing;
    }
}
