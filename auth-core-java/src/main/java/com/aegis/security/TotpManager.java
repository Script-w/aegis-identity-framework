package com.aegis.security;

import org.springframework.stereotype.Component;
import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
* TOTP helper for enrollment and verification (RFC6238 compatible).
* - Generates secrets, encodes/decodes them for storage (Base64 here).
* - Verifies codes using a TimeBasedOneTimePasswordGenerator.
*
* Note: store secrets encrypted at rest (use EncryptionService/Vault).
*/
@Component
public class TotpManager {
    private static final Duration TIME_STEP = Duration.ofSeconds(30);
    private static final String HMAC_ALGO = "HmacSHA1"; // compatible default
    private final TimeBasedOneTimePasswordGenerator totp;

    public TotpManager() throws NoSuchAlgorithmException {
        this.totp = new TimeBasedOneTimePasswordGenerator(TIME_STEP, 6, HMAC_ALGO);
    }

    public SecretKey generateSecret() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
        keyGen.init(160); // 160 bits for SHA-1
        return keyGen.generateKey();
    }

    public String secretToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public SecretKey secretFromBase64(String base64) {
        return new SecretKeySpec(Base64.getDecoder().decode(base64), "HmacSHA1");
    }

    public boolean verifyCode (SecretKey key, int code) throws InvalidKeyException {
        Instant now = Instant.now();
        int generated = totp.generateOneTimePassword(key, now);
        return generated == code;
    }
 
    public String getOtpAuthUri(String accountName, String issuer, SecretKey key) {
        String secret = secretToBase64(key);
        String label = URLEncoder.encode(issuer + ":" + accountName, StandardCharsets.UTF_8);
        return String.format("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=%s&digits=6&period=30", label, secret, URLEncoder.encode(issuer, StandardCharsets.UTF_8), "SHA1");
    }
}
