package com.xerika.auth.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

public final class PasswordUtil {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordUtil() {
    }

    public static Map<String, String> createArgon2Credential(String rawPassword) {
        int iterations = 5;
        int memoryKb = 7168;
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
            "\"hashIterations\":5," +
            "\"algorithm\":\"argon2\"," +
            "\"additionalParameters\":{" +
            "\"hashLength\":[\"32\"]," +
            "\"memory\":[\"7168\"]," +
            "\"type\":[\"id\"]," +
            "\"parallelism\":[\"1\"]" +
            "}" +
            "}";

        return Map.of("secretData", secretData, "credentialData", credentialData);
    }

    public static boolean verifyArgon2(String rawPassword, String secretDataJson, String credentialDataJson) {
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
