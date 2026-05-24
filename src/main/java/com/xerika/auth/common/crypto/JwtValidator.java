package com.xerika.auth.common.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

@ApplicationScoped
public class JwtValidator {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Inject
    RsaKeyProvider keys;

    @ConfigProperty(name = "auth.issuer.url", defaultValue = "http://localhost:8080")
    String expectedIssuer;

    public Optional<JsonNode> validate(String token) {
        return validateInternal(token, null, false);
    }

    /**
     * Validates the JWT and additionally enforces that its {@code aud} claim matches
     * {@code expectedAudience}. Use this overload from any caller that knows which
     * client a token should be bound to (e.g. an OIDC client validating an id_token
     * meant for itself). Passing {@code null} skips the aud check.
     */
    public Optional<JsonNode> validate(String token, String expectedAudience) {
        return validateInternal(token, expectedAudience, false);
    }

    /**
     * Validates signature + iss + (nbf) but tolerates an expired {@code exp}. Used
     * by /oauth/logout for the {@code id_token_hint}: OIDC RP-Initiated Logout 1.0
     * §3 says the OP SHOULD accept the hint regardless of expiry, because users
     * often log out after their id_token's lifetime has lapsed.
     */
    public Optional<JsonNode> validateAllowExpired(String token) {
        return validateInternal(token, null, true);
    }

    private Optional<JsonNode> validateInternal(String token, String expectedAudience, boolean allowExpired) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return Optional.empty();
        }

        try {
            JsonNode header = MAPPER.readTree(Base64.getUrlDecoder().decode(parts[0]));

            // Lock the algorithm. We only mint RS256; anything else (alg=none,
            // HS256, alg-confusion attempts) is rejected up-front instead of
            // relying on the hard-coded SHA256withRSA below to "happen to" fail.
            String alg = header.has("alg") ? header.get("alg").asText() : null;
            if (!"RS256".equals(alg)) {
                return Optional.empty();
            }

            // Strict kid lookup: if the header names a kid that we don't know,
            // reject outright instead of falling back to the active key. Without
            // this, a JWT signed by ANY key in our keystore would validate against
            // the active key's signature attempt and fail there — but the failure
            // path is the same as a forged token, which makes key-rotation bugs
            // harder to detect. Missing kid is allowed (legacy tokens / our own
            // pre-kid issuance) and uses the active key.
            String kid = header.has("kid") ? header.get("kid").asText() : null;
            PublicKey verifier;
            if (kid == null || kid.isBlank()) {
                verifier = keys.publicKey();
            } else {
                PublicKey resolved = keys.publicKeyByKid(kid).orElse(null);
                if (resolved == null) {
                    return Optional.empty();
                }
                verifier = resolved;
            }

            byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(verifier);
            signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
            if (!signature.verify(signatureBytes)) {
                return Optional.empty();
            }

            JsonNode payload = MAPPER.readTree(Base64.getUrlDecoder().decode(parts[1]));

            // Required claims: iss + exp. We mint both unconditionally; absence
            // means the token isn't one of ours (or the payload was tampered to
            // strip them after stripping the signature — impossible after the
            // verify above, but cheap to enforce).
            if (!payload.has("iss")
                || !expectedIssuer.equals(payload.get("iss").asText())) {
                return Optional.empty();
            }
            if (!payload.has("exp")) {
                return Optional.empty();
            }

            long now = Instant.now().getEpochSecond();
            if (!allowExpired && payload.get("exp").asLong() < now) {
                return Optional.empty();
            }
            if (payload.has("nbf") && payload.get("nbf").asLong() > now) {
                return Optional.empty();
            }

            if (expectedAudience != null && !audienceMatches(payload.get("aud"), expectedAudience)) {
                return Optional.empty();
            }

            return Optional.of(payload);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    // RFC 7519 §4.1.3 — aud may be a single string or an array of strings.
    private static boolean audienceMatches(JsonNode aud, String expected) {
        if (aud == null || aud.isNull()) {
            return false;
        }
        if (aud.isTextual()) {
            return expected.equals(aud.asText());
        }
        if (aud.isArray()) {
            for (JsonNode v : aud) {
                if (v.isTextual() && expected.equals(v.asText())) {
                    return true;
                }
            }
        }
        return false;
    }
}
