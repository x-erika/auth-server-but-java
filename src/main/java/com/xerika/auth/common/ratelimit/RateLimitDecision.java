package com.xerika.auth.common.ratelimit;

public record RateLimitDecision(boolean allowed, long count, long retryAfterSeconds) {

    public static RateLimitDecision allowed(long count) {
        return new RateLimitDecision(true, count, 0);
    }

    public static RateLimitDecision denied(long count, long retryAfterSeconds) {
        return new RateLimitDecision(false, count, retryAfterSeconds);
    }

    public static RateLimitDecision failOpen() {
        return new RateLimitDecision(true, 0, 0);
    }
}
