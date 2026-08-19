package com.aegis.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class MfaSecretProtector {
    private static final String PREFIX = "v1:";
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final SecretKeySpec key;
    private final SecureRandom secureRandom;

    @Autowired
    public MfaSecretProtector(@Value("${mfa.encryption-key}") String encodedKey) {
        this(encodedKey, new SecureRandom());
    }

    MfaSecretProtector(String encodedKey, SecureRandom secureRandom) {
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(encodedKey);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("mfa.encryption-key must be valid Base64", exception);
        }
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException("mfa.encryption-key must decode to exactly 32 bytes");
        }
        this.key = new SecretKeySpec(keyBytes, "AES");
        this.secureRandom = secureRandom;
    }

    public String protect(String plaintext) {
        if (plaintext == null || plaintext.isBlank()) {
            return plaintext;
        }
        byte[] nonce = new byte[NONCE_BYTES];
        secureRandom.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] envelope = ByteBuffer.allocate(nonce.length + ciphertext.length)
                    .put(nonce)
                    .put(ciphertext)
                    .array();
            return PREFIX + Base64.getEncoder().encodeToString(envelope);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to encrypt MFA secret", exception);
        }
    }

    public String unprotect(String storedValue) {
        if (storedValue == null || storedValue.isBlank() || !isProtected(storedValue)) {
            return storedValue;
        }
        try {
            byte[] envelope = Base64.getDecoder().decode(storedValue.substring(PREFIX.length()));
            if (envelope.length <= NONCE_BYTES) {
                throw new IllegalArgumentException("Encrypted MFA secret is malformed");
            }
            byte[] nonce = new byte[NONCE_BYTES];
            byte[] ciphertext = new byte[envelope.length - NONCE_BYTES];
            System.arraycopy(envelope, 0, nonce, 0, NONCE_BYTES);
            System.arraycopy(envelope, NONCE_BYTES, ciphertext, 0, ciphertext.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new IllegalStateException("Unable to decrypt MFA secret", exception);
        }
    }

    public boolean isProtected(String storedValue) {
        return storedValue != null && storedValue.startsWith(PREFIX);
    }
}
