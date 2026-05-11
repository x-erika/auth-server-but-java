package com.xerika.auth.common.crypto;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Argon2HasherTest {

    @Test
    void hashAndVerifyRoundTrip() {
        Map<String, String> cred = Argon2Hasher.hash("supersecret123");
        assertTrue(Argon2Hasher.verify("supersecret123", cred.get("secretData"), cred.get("credentialData")));
    }

    @Test
    void wrongPasswordFails() {
        Map<String, String> cred = Argon2Hasher.hash("correct");
        assertFalse(Argon2Hasher.verify("wrong", cred.get("secretData"), cred.get("credentialData")));
    }

    @Test
    void emptyPasswordVerifies() {
        Map<String, String> cred = Argon2Hasher.hash("");
        assertTrue(Argon2Hasher.verify("", cred.get("secretData"), cred.get("credentialData")));
        assertFalse(Argon2Hasher.verify("nonempty", cred.get("secretData"), cred.get("credentialData")));
    }

    @Test
    void differentSaltsProduceDifferentHashes() {
        Map<String, String> a = Argon2Hasher.hash("same-password");
        Map<String, String> b = Argon2Hasher.hash("same-password");
        assertNotEquals(a.get("secretData"), b.get("secretData"));
    }

    @Test
    void verifyHandlesMalformedJsonGracefully() {
        assertFalse(Argon2Hasher.verify("any", "not-json", "not-json"));
    }
}
