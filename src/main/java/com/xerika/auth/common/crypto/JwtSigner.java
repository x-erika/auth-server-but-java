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
}
