package com.aegis.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {
    private static final String SECRET = "test-secret-that-is-at-least-32-bytes-long";

    @Test
    void generatedTokenCanBeValidated() {
        JwtService jwtService = new JwtService(SECRET, 3600000);

        String token = jwtService.generateToken("alice");

        assertEquals("alice", jwtService.extractUsername(token));
        assertTrue(jwtService.isValid(token, "alice"));
        assertFalse(jwtService.isValid(token, "bob"));
    }

    @Test
    void invalidSecretAndExpirationAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new JwtService("short", 3600000));
        assertThrows(IllegalArgumentException.class, () -> new JwtService(SECRET, 0));
    }
}
