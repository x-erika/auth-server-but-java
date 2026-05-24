package com.xerika.auth.common.crypto;

import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * HMAC-SHA256 utility used for at-rest hashes of high-value opaque tokens
 * (refresh tokens, password reset tokens). The point over plain SHA-256 is
 * defence against a DB-only leak: an attacker with the raw {@code token_hash}
 * column still needs the server-side HMAC key to grind candidates, so a
 * compromised DB snapshot alone doesn't yield usable tokens.
 *
 * <p>The key is sourced from {@code auth.token-hmac.key} (env var
 * {@code AUTH_TOKEN_HMAC_KEY}). The dev default is a placeholder — operators
 * MUST set a long random value in production; rotating it invalidates every
 * currently-issued refresh token (the hashes won't match), which is the
 * intended emergency-rotation behaviour.
 */
@ApplicationScoped
public class HmacSha256 {

    @ConfigProperty(
        name = "auth.token-hmac.key",
        defaultValue = "dev-only-hmac-key-do-not-use-in-production-please-rotate-via-env"
    )
    String hmacKey;

    public String compute(String value) {
        if (value == null) {
            throw new IllegalArgumentException("value is required");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] digest = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }
}
