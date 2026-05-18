package com.xerika.auth.common.crypto;

import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

@ApplicationScoped
public class JwtSigner {

    @Inject
    RsaKeyProvider keys;

    @ConfigProperty(name = "auth.issuer.url", defaultValue = "http://localhost:8080")
    String issuer;

    @ConfigProperty(name = "auth.jwt.access-token-ttl-seconds", defaultValue = "900")
    long accessTokenTtlSeconds;

    @ConfigProperty(name = "auth.jwt.id-token-ttl-seconds", defaultValue = "3600")
    long idTokenTtlSeconds;

    public String issuer() {
        return issuer;
    }

    public long accessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    public long idTokenTtlSeconds() {
        return idTokenTtlSeconds;
    }

    public String signAccessToken(String subject, String audience, Map<String, Object> extraClaims) {
        JwtClaimsBuilder builder = baseClaims(subject, audience, Duration.ofSeconds(accessTokenTtlSeconds));
        applyClaims(builder, extraClaims);
        // RFC 9068 §2.1 — access tokens use `typ: at+jwt` so resource servers can
        // distinguish them from id tokens that happen to flow through the same path.
        return signedWithType(builder, "at+jwt");
    }

    public String signLogoutToken(String subject, String audience, String sessionId) {
        Map<String, Object> events = new java.util.LinkedHashMap<>();
        events.put("http://schemas.openid.net/event/backchannel-logout", new java.util.LinkedHashMap<>());

        JwtClaimsBuilder builder = Jwt.issuer(issuer)
            .audience(audience)
            .claim("jti", UUID.randomUUID().toString())
            .claim("iat", java.time.Instant.now().getEpochSecond())
            .claim("events", events)
            .claim("sid", sessionId);

        if (subject != null && !subject.isBlank()) {
            builder.subject(subject);
        }

        return signed(builder);
    }

    public String signIdToken(
        String subject,
        String audience,
        String nonce,
        long authTime,
        Map<String, Object> extraClaims
    ) {
        JwtClaimsBuilder builder = baseClaims(subject, audience, Duration.ofSeconds(idTokenTtlSeconds))
            .claim("auth_time", authTime);

        if (nonce != null && !nonce.isBlank()) {
            builder.claim("nonce", nonce);
        }

        applyClaims(builder, extraClaims);
        return signed(builder);
    }

    private JwtClaimsBuilder baseClaims(String subject, String audience, Duration ttl) {
        return Jwt.issuer(issuer)
            .audience(audience)
            .subject(subject)
            .claim("jti", UUID.randomUUID().toString())
            .expiresIn(ttl);
    }

    private void applyClaims(JwtClaimsBuilder builder, Map<String, Object> claims) {
        if (claims == null) {
            return;
        }
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }
    }

    private String signed(JwtClaimsBuilder builder) {
        return builder
            .jws()
            .keyId(keys.keyId())
            .sign(keys.privateKey());
    }

    private String signedWithType(JwtClaimsBuilder builder, String typ) {
        return builder
            .jws()
            .keyId(keys.keyId())
            .header("typ", typ)
            .sign(keys.privateKey());
    }
}
