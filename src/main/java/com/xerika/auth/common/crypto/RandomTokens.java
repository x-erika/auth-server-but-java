package com.xerika.auth.common.crypto;

import java.security.SecureRandom;
import java.util.Base64;

public final class RandomTokens {

    private static final SecureRandom RANDOM = new SecureRandom();

    private RandomTokens() {
    }

    public static String urlSafe(int byteLength) {
        byte[] bytes = new byte[byteLength];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
