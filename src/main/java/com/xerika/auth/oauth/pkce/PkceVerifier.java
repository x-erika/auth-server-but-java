package com.xerika.auth.oauth.pkce;

import com.xerika.auth.common.crypto.Sha256;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.Set;

@ApplicationScoped
public class PkceVerifier {

    private static final Set<String> SUPPORTED_METHODS = Set.of("S256", "plain");

    public boolean isMethodSupported(String method) {
        return method != null && SUPPORTED_METHODS.contains(method);
    }

    public boolean verify(String codeVerifier, String codeChallenge, String method) {
        if (codeVerifier == null || codeChallenge == null || method == null) {
            return false;
        }

        if ("plain".equalsIgnoreCase(method)) {
            return codeVerifier.equals(codeChallenge);
        }

        if ("S256".equalsIgnoreCase(method)) {
            return Sha256.base64Url(codeVerifier).equals(codeChallenge);
        }

        return false;
    }
}
