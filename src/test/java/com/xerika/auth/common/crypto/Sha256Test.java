package com.xerika.auth.common.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Sha256Test {

    @Test
    void deterministicForSameInput() {
        assertEquals(Sha256.base64Url("xerika"), Sha256.base64Url("xerika"));
    }

    @Test
    void differentInputDifferentOutput() {
        assertNotEquals(Sha256.base64Url("a"), Sha256.base64Url("b"));
    }

    @Test
    void produces43CharOutput() {
        assertEquals(43, Sha256.base64Url("anything").length());
        assertEquals(43, Sha256.base64Url("").length());
    }

    @Test
    void usesUrlSafeAlphabet() {
        for (int i = 0; i < 50; i++) {
            String hash = Sha256.base64Url("input-" + i);
            assertTrue(hash.matches("[A-Za-z0-9_-]+"), "expected url-safe, got: " + hash);
        }
    }
}
