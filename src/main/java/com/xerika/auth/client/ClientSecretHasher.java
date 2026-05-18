package com.xerika.auth.client;

import com.xerika.auth.common.crypto.Argon2Hasher;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;

/**
 * Hashes / verifies confidential client secrets at rest.
 *
 * <p>Storage format: {@code secretData|credentialData} — the two halves of an
 * Argon2id hash returned by {@link Argon2Hasher#hash(String)}, joined by a pipe
 * so they fit in a single TEXT column. The leading {@code {} of {@code secretData}
 * lets us cheaply detect this format vs. legacy plaintext rows.
 *
 * <p>{@link #verify} accepts both the new format and legacy plaintext (constant-time
 * compare) so deployments with existing plaintext rows keep working until the
 * admin rotates each secret. New writes always use the hashed format.
 */
public final class ClientSecretHasher {

    private ClientSecretHasher() {
    }

    public static String hash(String rawSecret) {
        Map<String, String> parts = Argon2Hasher.hash(rawSecret);
        return parts.get("secretData") + "|" + parts.get("credentialData");
    }

    public static boolean verify(String presented, String stored) {
        if (presented == null || stored == null) {
            return false;
        }
        int sep = stored.indexOf('|');
        if (sep > 0 && stored.startsWith("{")) {
            String secretData = stored.substring(0, sep);
            String credentialData = stored.substring(sep + 1);
            return Argon2Hasher.verify(presented, secretData, credentialData);
        }
        // Legacy plaintext path — kept so old deployments don't break, but flagged
        // in README so it's clear this is a transitional state, not the intent.
        byte[] a = presented.getBytes(StandardCharsets.UTF_8);
        byte[] b = stored.getBytes(StandardCharsets.UTF_8);
        return a.length == b.length && MessageDigest.isEqual(a, b);
    }

    /** True if {@code stored} is already in the new hashed format. */
    public static boolean isHashed(String stored) {
        return stored != null && stored.startsWith("{") && stored.indexOf('|') > 0;
    }
}
