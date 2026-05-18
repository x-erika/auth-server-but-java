package com.xerika.auth.common.ratelimit;

import com.xerika.auth.common.redis.RedisLua;
import io.quarkus.redis.datasource.RedisDataSource;
import io.vertx.mutiny.redis.client.Response;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response.Status;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Map;

@ApplicationScoped
public class RateLimiter {

    private static final Logger LOG = Logger.getLogger(RateLimiter.class);

    @Inject
    RedisDataSource redis;

    @Inject
    RedisLua lua;

    public RateLimitDecision check(String key, int limit, long windowSeconds) {
        if (key == null || key.isEmpty()) {
            return RateLimitDecision.failOpen();
        }
        if (limit <= 0 || windowSeconds <= 0) {
            return RateLimitDecision.failOpen();
        }
        try {
            Response r = lua.eval(
                RedisLua.INCR_AND_EXPIRE,
                List.of(key),
                List.of(Long.toString(windowSeconds))
            );
            if (r == null) {
                return RateLimitDecision.failOpen();
            }
            long count = r.toLong();
            if (count > limit) {
                long retryAfter = readTtlOrDefault(key, windowSeconds);
                return RateLimitDecision.denied(count, retryAfter);
            }
            return RateLimitDecision.allowed(count);
        } catch (Exception e) {
            LOG.warnf(e, "Rate limit check failed for key %s, failing open", key);
            return RateLimitDecision.failOpen();
        }
    }

    public static jakarta.ws.rs.core.Response tooManyRequests(RateLimitDecision decision) {
        return jakarta.ws.rs.core.Response.status(Status.TOO_MANY_REQUESTS)
            .header("Retry-After", String.valueOf(decision.retryAfterSeconds()))
            .entity(Map.of(
                "error", "rate_limit_exceeded",
                "retry_after_seconds", decision.retryAfterSeconds()
            ))
            .build();
    }

    private long readTtlOrDefault(String key, long fallback) {
        try {
            Response ttl = redis.execute("TTL", key);
            if (ttl == null) {
                return fallback;
            }
            long sec = ttl.toLong();
            return sec > 0 ? sec : fallback;
        } catch (Exception e) {
            return fallback;
        }
    }
}
