package com.xerika.auth.oauth.pkce;

import com.xerika.auth.common.crypto.Sha256;
import jakarta.enterprise.context.ApplicationScoped;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Set;

@ApplicationScoped
public class PkceVerifier {

    // OAuth 2.0 Security BCP §2.1.1.1 / RFC 9700: "plain" MUST NOT be used.
    // Only S256 is accepted — clients are responsible for hashing the verifier.
    private static final Set<String> SUPPORTED_METHODS = Set.of("S256");

    public boolean isMethodSupported(String method) {
        return method != null && SUPPORTED_METHODS.contains(method);
    }

    public boolean verify(String codeVerifier, String codeChallenge, String method) {
        if (codeVerifier == null || codeChallenge == null || method == null) {
            return false;
        }

        if (!"S256".equalsIgnoreCase(method)) {
            return false;
        }

        byte[] computed = Sha256.base64Url(codeVerifier).getBytes(StandardCharsets.UTF_8);
        byte[] stored = codeChallenge.getBytes(StandardCharsets.UTF_8);
        return computed.length == stored.length && MessageDigest.isEqual(computed, stored);
    }
}
