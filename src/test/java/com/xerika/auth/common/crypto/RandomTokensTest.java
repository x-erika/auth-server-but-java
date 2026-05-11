package com.xerika.auth.common.crypto;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RandomTokensTest {

    @Test
    void successiveCallsAreUnique() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            seen.add(RandomTokens.urlSafe(32));
        }
        assertEquals(1000, seen.size(), "duplicate tokens generated");
    }

    @Test
    void length32BytesProduces43Chars() {
        assertEquals(43, RandomTokens.urlSafe(32).length());
    }

    @Test
    void length48BytesProduces64Chars() {
        assertEquals(64, RandomTokens.urlSafe(48).length());
    }

    @Test
    void useUrlSafeAlphabetOnly() {
        for (int i = 0; i < 50; i++) {
            String token = RandomTokens.urlSafe(48);
            assertTrue(token.matches("[A-Za-z0-9_-]+"), "non-urlsafe char in: " + token);
        }
    }
}
