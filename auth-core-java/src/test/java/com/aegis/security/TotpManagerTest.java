package com.aegis.security;

import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class TotpManagerTest {
    private final TotpManager totpManager = new TotpManager();

    TotpManagerTest() throws Exception {
    }

    @Test
    void secretRoundTripPreservesKeyBytes() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("HmacSHA1");
        generator.init(160);
        SecretKey original = generator.generateKey();

        SecretKey restored = totpManager.secretFromBase64(totpManager.secretToBase64(original));

        assertArrayEquals(original.getEncoded(), restored.getEncoded());
        assertEquals("HmacSHA1", restored.getAlgorithm());
    }

    @Test
    void otpAuthUriContainsEncodedAccountAndIssuer() throws Exception {
        SecretKey key = totpManager.generateSecret();

        String uri = totpManager.getOtpAuthUri("alice@example.test", "Aegis Identity", key);

        assertTrue(uri.startsWith("otpauth://totp/"));
        assertTrue(uri.contains("secret="));
        assertTrue(uri.contains("issuer=Aegis+Identity"));
        assertEquals("Aegis Identity:alice@example.test",
                URLDecoder.decode(uri.substring("otpauth://totp/".length(),
                        uri.indexOf("?")), StandardCharsets.UTF_8));
        assertTrue(uri.contains("algorithm=SHA1"));
        assertTrue(uri.contains("digits=6"));
        assertTrue(uri.contains("period=30"));
    }

    @Test
    void verifyCodeRejectsAnIncorrectCode() throws Exception {
        SecretKey key = totpManager.generateSecret();

        assertFalse(totpManager.verifyCode(key, 0));
    }
}
