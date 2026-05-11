package com.xerika.auth.oauth;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScopesTest {

    @Test
    void parseNullReturnsEmpty() {
        assertTrue(Scopes.parse(null).isEmpty());
    }

    @Test
    void parseBlankReturnsEmpty() {
        assertTrue(Scopes.parse("").isEmpty());
        assertTrue(Scopes.parse("   ").isEmpty());
    }

    @Test
    void parseSpaceSeparated() {
        assertEquals(Set.of("openid", "profile", "email"), Scopes.parse("openid profile email"));
    }

    @Test
    void parseCommaSeparated() {
        assertEquals(Set.of("openid", "profile"), Scopes.parse("openid, profile"));
    }

    @Test
    void parseSkipsBlanks() {
        assertEquals(Set.of("a", "b"), Scopes.parse("a   b"));
    }

    @Test
    void isSubsetOf_emptyRequestedAlwaysAllowed() {
        assertTrue(Scopes.isSubsetOf(null, "openid"));
        assertTrue(Scopes.isSubsetOf("", "openid"));
    }

    @Test
    void isSubsetOf_emptyAllowedRejectsAnything() {
        assertFalse(Scopes.isSubsetOf("openid", null));
        assertFalse(Scopes.isSubsetOf("openid", ""));
    }

    @Test
    void isSubsetOf_properSubsetTrue() {
        assertTrue(Scopes.isSubsetOf("openid", "openid profile email"));
        assertTrue(Scopes.isSubsetOf("openid profile", "openid profile email"));
    }

    @Test
    void isSubsetOf_notSubsetFalse() {
        assertFalse(Scopes.isSubsetOf("admin", "openid profile"));
        assertFalse(Scopes.isSubsetOf("openid admin", "openid profile"));
    }
}
