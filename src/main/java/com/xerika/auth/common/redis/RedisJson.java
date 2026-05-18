package com.xerika.auth.common.redis;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class RedisJson {

    private final ObjectMapper mapper;

    public RedisJson() {
        this.mapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .disable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES);
    }

    public String stringify(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalStateException("Redis JSON serialize failed", e);
        }
    }

    public <T> T parse(String raw, Class<T> type) {
        if (raw == null) {
            return null;
        }
        try {
            return mapper.readValue(raw, type);
        } catch (Exception e) {
            throw new IllegalStateException(
                "Redis JSON deserialize failed for " + type.getSimpleName(), e);
        }
    }
}
