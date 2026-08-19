package com.aegis.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordHasherTest {
    private final PasswordHasher passwordHasher = new PasswordHasher();

    @Test
    void hashAndVerifyRoundTripWipesCharArray() {
        char[] password = "correct-password".toCharArray();

        String encoded = passwordHasher.hash(password);

        assertTrue(encoded.startsWith("$argon2id$"));
        assertArrayEquals(new char[password.length], password);
        assertTrue(passwordHasher.verify(encoded, "correct-password".toCharArray()));
    }

    @Test
    void verifyRejectsWrongPassword() {
        String encoded = passwordHasher.hash("correct-password");
        char[] wrongPassword = "wrong-password".toCharArray();

        assertFalse(passwordHasher.verify(encoded, wrongPassword));
        assertArrayEquals(new char[wrongPassword.length], wrongPassword);
    }
}
