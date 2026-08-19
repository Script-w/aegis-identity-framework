package com.aegis.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MfaSecretProtectorTest {
    private static final String KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    private final MfaSecretProtector protector = new MfaSecretProtector(KEY);

    @Test
    void encryptsAndDecryptsSecret() {
        String encrypted = protector.protect("JBSWY3DPEHPK3PXP");

        assertTrue(encrypted.startsWith("v1:"));
        assertEquals("JBSWY3DPEHPK3PXP", protector.unprotect(encrypted));
    }

    @Test
    void usesFreshNonceForEveryEncryption() {
        assertNotEquals(
                protector.protect("JBSWY3DPEHPK3PXP"),
                protector.protect("JBSWY3DPEHPK3PXP")
        );
    }

    @Test
    void readsLegacyPlaintextForMigration() {
        assertEquals("JBSWY3DPEHPK3PXP", protector.unprotect("JBSWY3DPEHPK3PXP"));
    }

    @Test
    void rejectsTamperedCiphertext() {
        String encrypted = protector.protect("JBSWY3DPEHPK3PXP");
        String tampered = encrypted.substring(0, encrypted.length() - 2) + "AA";

        assertThrows(IllegalStateException.class, () -> protector.unprotect(tampered));
    }

    @Test
    void rejectsWrongLengthKey() {
        assertThrows(IllegalArgumentException.class, () -> new MfaSecretProtector("dG9vLXNob3J0"));
    }
}
