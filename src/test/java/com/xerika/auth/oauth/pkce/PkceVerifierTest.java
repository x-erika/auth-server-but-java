package com.xerika.auth.oauth.pkce;

import com.xerika.auth.common.crypto.Sha256;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PkceVerifierTest {

    private final PkceVerifier verifier = new PkceVerifier();

    @Test
    void s256_validVerifierMatchesChallenge() {
        String codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String codeChallenge = Sha256.base64Url(codeVerifier);
        assertTrue(verifier.verify(codeVerifier, codeChallenge, "S256"));
    }

    @Test
    void s256_mismatchReturnsFalse() {
        String challenge = Sha256.base64Url("real-verifier");
        assertFalse(verifier.verify("wrong-verifier", challenge, "S256"));
    }

    @Test
    void plain_matchTrue() {
        assertTrue(verifier.verify("identical", "identical", "plain"));
    }

    @Test
    void plain_mismatchFalse() {
        assertFalse(verifier.verify("a", "b", "plain"));
    }

    @Test
    void nullInputsReturnFalse() {
        assertFalse(verifier.verify(null, "c", "S256"));
        assertFalse(verifier.verify("v", null, "S256"));
        assertFalse(verifier.verify("v", "c", null));
    }

    @Test
    void unsupportedMethodReturnsFalse() {
        assertFalse(verifier.verify("v", "c", "MD5"));
    }

    @Test
    void methodSupportedCheck() {
        assertTrue(verifier.isMethodSupported("S256"));
        assertTrue(verifier.isMethodSupported("plain"));
        assertFalse(verifier.isMethodSupported("S512"));
        assertFalse(verifier.isMethodSupported(null));
        assertFalse(verifier.isMethodSupported(""));
    }
}
