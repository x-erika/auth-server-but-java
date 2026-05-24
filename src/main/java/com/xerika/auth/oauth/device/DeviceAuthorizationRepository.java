package com.xerika.auth.oauth.device;

import com.xerika.auth.common.redis.RedisKeys;
import io.quarkus.redis.datasource.RedisDataSource;
import io.vertx.mutiny.redis.client.Response;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@ApplicationScoped
public class DeviceAuthorizationRepository {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    @Inject
    RedisDataSource redis;

    public Optional<DeviceAuthorization> findByDeviceCode(String deviceCode) {
        if (deviceCode == null || deviceCode.isEmpty()) {
            return Optional.empty();
        }
        return loadHash(RedisKeys.deviceByCode(deviceCode));
    }

    public Optional<DeviceAuthorization> findByUserCode(String userCode) {
        if (userCode == null || userCode.isEmpty()) {
            return Optional.empty();
        }
        // RFC 8628 §6.1 — user_code SHOULD be case-insensitive and tolerant of
        // separators (hyphens/whitespace) that the user might or might not type.
        Response ptr = redis.execute("GET", RedisKeys.deviceByUserCode(normalizeUserCode(userCode)));
        if (ptr == null) {
            return Optional.empty();
        }
        String dc = ptr.toString();
        if (dc == null || dc.isEmpty()) {
            return Optional.empty();
        }
        return findByDeviceCode(dc);
    }

    /**
     * Atomic SET-NX for the user_code → device_code pointer. Returns true if the
     * pointer was new; false if a collision was detected so the caller can
     * regenerate a fresh user_code.
     */
    public boolean persist(DeviceAuthorization auth) {
        if (auth.expiresAt == null) {
            throw new IllegalArgumentException("DeviceAuthorization.expiresAt is required");
        }
        long ttl = Duration.between(LocalDateTime.now(), auth.expiresAt).getSeconds();
        if (ttl <= 0) {
            return false;
        }
        String mainKey = RedisKeys.deviceByCode(auth.deviceCode);
        String pointerKey = RedisKeys.deviceByUserCode(normalizeUserCode(auth.userCode));

        // SET NX on the pointer first — if it already exists we have a user_code
        // collision; bail without touching the main hash so the caller can retry.
        Response ptrResult = redis.execute("SET", pointerKey, auth.deviceCode, "EX", Long.toString(ttl), "NX");
        if (ptrResult == null) {
            return false;
        }

        Map<String, String> fields = toFields(auth);
        redis.execute("HSET", flatten(mainKey, fields));
        redis.execute("EXPIRE", mainKey, Long.toString(ttl));
        return true;
    }

    private static String normalizeUserCode(String userCode) {
        if (userCode == null) {
            return "";
        }
        return userCode.replaceAll("[\\s-]", "").toUpperCase(Locale.ROOT);
    }

    public DeviceAuthorization update(DeviceAuthorization auth) {
        if (auth.deviceCode == null) {
            return auth;
        }
        String mainKey = RedisKeys.deviceByCode(auth.deviceCode);
        Response exists = redis.execute("EXISTS", mainKey);
        if (exists == null || exists.toLong() == 0L) {
            return auth;
        }
        Map<String, String> fields = toFields(auth);
        redis.execute("HSET", flatten(mainKey, fields));
        return auth;
    }

    private Optional<DeviceAuthorization> loadHash(String key) {
        Response r = redis.execute("HGETALL", key);
        if (r == null) {
            return Optional.empty();
        }
        Map<String, String> fields = new LinkedHashMap<>();
        try {
            Set<String> hashKeys = r.getKeys();
            if (hashKeys == null || hashKeys.isEmpty()) {
                return Optional.empty();
            }
            for (String k : hashKeys) {
                Response v = r.get(k);
                if (v != null) {
                    fields.put(k, v.toString());
                }
            }
        } catch (Exception e) {
            if (r.size() == 0) {
                return Optional.empty();
            }
            for (int i = 0; i + 1 < r.size(); i += 2) {
                fields.put(r.get(i).toString(), r.get(i + 1).toString());
            }
        }
        return Optional.of(fromFields(fields));
    }

    private static String[] flatten(String key, Map<String, String> fields) {
        String[] out = new String[1 + fields.size() * 2];
        out[0] = key;
        int i = 1;
        for (Map.Entry<String, String> e : fields.entrySet()) {
            out[i++] = e.getKey();
            out[i++] = e.getValue();
        }
        return out;
    }

    private static Map<String, String> toFields(DeviceAuthorization auth) {
        Map<String, String> m = new LinkedHashMap<>();
        putIfNotNull(m, "id", auth.id == null ? null : auth.id.toString());
        putIfNotNull(m, "deviceCode", auth.deviceCode);
        putIfNotNull(m, "userCode", auth.userCode);
        putIfNotNull(m, "clientId", auth.clientId);
        putIfNotNull(m, "scope", auth.scope);
        putIfNotNull(m, "status", auth.status);
        putIfNotNull(m, "userId", auth.userId == null ? null : auth.userId.toString());
        putIfNotNull(m, "sessionId", auth.sessionId == null ? null : auth.sessionId.toString());
        putIfNotNull(m, "expiresAt", auth.expiresAt == null ? null : auth.expiresAt.format(FMT));
        putIfNotNull(m, "createdAt", auth.createdAt == null ? null : auth.createdAt.format(FMT));
        return m;
    }

    private static DeviceAuthorization fromFields(Map<String, String> m) {
        DeviceAuthorization a = new DeviceAuthorization();
        if (m.containsKey("id")) {
            a.id = UUID.fromString(m.get("id"));
        }
        a.deviceCode = m.get("deviceCode");
        a.userCode = m.get("userCode");
        a.clientId = m.get("clientId");
        a.scope = m.get("scope");
        a.status = m.get("status");
        if (m.get("userId") != null) {
            a.userId = UUID.fromString(m.get("userId"));
        }
        if (m.get("sessionId") != null) {
            a.sessionId = UUID.fromString(m.get("sessionId"));
        }
        if (m.get("expiresAt") != null) {
            a.expiresAt = LocalDateTime.parse(m.get("expiresAt"), FMT);
        }
        if (m.get("createdAt") != null) {
            a.createdAt = LocalDateTime.parse(m.get("createdAt"), FMT);
        }
        return a;
    }

    private static void putIfNotNull(Map<String, String> m, String k, String v) {
        if (v != null) {
            m.put(k, v);
        }
    }
}
