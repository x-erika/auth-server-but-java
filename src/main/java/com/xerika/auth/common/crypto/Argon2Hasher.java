package com.xerika.auth.common.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.Semaphore;

public final class Argon2Hasher {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    // Caps concurrent Argon2 hashes. Argon2 is CPU-bound (~25ms) and each call
    // allocates `memoryKb` (12 MiB); Quarkus's worker pool would otherwise run
    // hundreds in parallel, exploding RSS without adding throughput (the work
    // is CPU-bound). Bound at the core count so memory stays predictable and
    // throughput sits at the CPU ceiling. Override: AUTH_ARGON2_MAX_CONCURRENCY.
    private static final Semaphore ARGON2_PERMITS = new Semaphore(maxConcurrency(), true);

    private static int maxConcurrency() {
        String env = System.getenv("AUTH_ARGON2_MAX_CONCURRENCY");
        if (env != null) {
            try {
                int n = Integer.parseInt(env.trim());
                if (n > 0) {
                    return n;
                }
            } catch (NumberFormatException ignored) {
            }
        }
        return Math.max(1, Runtime.getRuntime().availableProcessors());
    }

    private Argon2Hasher() {
    }

    public static Map<String, String> hash(String rawPassword) {
        // OWASP 2024 Argon2id baseline (12 MiB memory, 3 iterations, p=1).
        // Old credentials remain verifiable because verify() reads each row's
        // own stored params from credentialData JSON, so existing hashes don't
        // break — only new writes use the stronger settings.
        int iterations = 3;
        int memoryKb = 12288;
        int parallelism = 1;
        int hashLength = 32;
        int type = Argon2Parameters.ARGON2_id;

        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);

        byte[] hash = argon2(rawPassword, salt, iterations, memoryKb, parallelism, hashLength, type);

        String secretData = "{" +
            "\"value\":\"" + Base64.getEncoder().encodeToString(hash) + "\"," +
            "\"salt\":\"" + Base64.getEncoder().encodeToString(salt) + "\"," +
            "\"additionalParameters\":{}" +
            "}";

        String credentialData = "{" +
            "\"hashIterations\":" + iterations + "," +
            "\"algorithm\":\"argon2\"," +
            "\"additionalParameters\":{" +
            "\"hashLength\":[\"" + hashLength + "\"]," +
            "\"memory\":[\"" + memoryKb + "\"]," +
            "\"type\":[\"id\"]," +
            "\"parallelism\":[\"" + parallelism + "\"]" +
            "}" +
            "}";

        return Map.of("secretData", secretData, "credentialData", credentialData);
    }

    public static boolean verify(String rawPassword, String secretDataJson, String credentialDataJson) {
        try {
            JsonNode secret = MAPPER.readTree(secretDataJson);
            JsonNode credential = MAPPER.readTree(credentialDataJson);

            byte[] expected = Base64.getDecoder().decode(secret.path("value").asText());
            byte[] salt = Base64.getDecoder().decode(secret.path("salt").asText());

            int iterations = credential.path("hashIterations").asInt(5);
            JsonNode params = credential.path("additionalParameters");
            int hashLength = firstInt(params, "hashLength", 32);
            int memory = firstInt(params, "memory", 7168);
            int parallelism = firstInt(params, "parallelism", 1);
            int type = parseArgon2Type(firstText(params, "type", "id"));

            byte[] actual = argon2(rawPassword, salt, iterations, memory, parallelism, hashLength, type);
            return MessageDigest.isEqual(expected, actual);
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] argon2(String rawPassword, byte[] salt, int iterations, int memoryKb, int parallelism, int hashLength, int type) {
        try {
            ARGON2_PERMITS.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Argon2 interrupted while waiting for a permit", e);
        }
        try {
            Argon2Parameters parameters = new Argon2Parameters.Builder(type)
                .withSalt(salt)
                .withIterations(iterations)
                .withMemoryAsKB(memoryKb)
                .withParallelism(parallelism)
                .build();

            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(parameters);

            byte[] output = new byte[hashLength];
            generator.generateBytes(rawPassword.getBytes(StandardCharsets.UTF_8), output);
            return output;
        } finally {
            ARGON2_PERMITS.release();
        }
    }

    private static int parseArgon2Type(String type) {
        return switch (type.toLowerCase()) {
            case "d" -> Argon2Parameters.ARGON2_d;
            case "i" -> Argon2Parameters.ARGON2_i;
            default -> Argon2Parameters.ARGON2_id;
        };
    }

    private static int firstInt(JsonNode parent, String key, int fallback) {
        JsonNode node = parent.path(key);
        if (node.isArray() && node.size() > 0) {
            return Integer.parseInt(node.get(0).asText(String.valueOf(fallback)));
        }
        return fallback;
    }

    private static String firstText(JsonNode parent, String key, String fallback) {
        JsonNode node = parent.path(key);
        if (node.isArray() && node.size() > 0) {
            return node.get(0).asText(fallback);
        }
        return fallback;
    }
}
