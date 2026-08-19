package com.aegis.service;

import com.aegis.model.User;
import com.aegis.repository.UserRepository;
import com.aegis.security.PasswordHasher;
import com.aegis.security.MfaSecretProtector;
import com.aegis.security.LoginAttemptPolicy;
import com.aegis.security.TotpManager;
import com.aegis.service.MfaClient.MfaSetupResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;

@Service
public class AuthService {
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final MfaClient mfaClient;
    private final TotpManager totpManager;
    private final MfaSecretProtector mfaSecretProtector;
    private final LoginAttemptPolicy loginAttemptPolicy;

    public AuthService(UserRepository userRepository, PasswordHasher passwordHasher,
                       MfaClient mfaClient, TotpManager totpManager,
                       MfaSecretProtector mfaSecretProtector,
                       LoginAttemptPolicy loginAttemptPolicy) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.mfaClient = mfaClient;
        this.totpManager = totpManager;
        this.mfaSecretProtector = mfaSecretProtector;
        this.loginAttemptPolicy = loginAttemptPolicy;
    }

    public MfaSetupResult initiateMfaSetup(String username) {
        return userRepository.findByUsername(username)
            .map(user -> {
                String storedSecret = user.getMfaSecret();
                String secret;
                if (storedSecret == null || storedSecret.isBlank()) {
                    try {
                        secret = totpManager.secretToBase32(totpManager.generateSecret());
                    } catch (java.security.NoSuchAlgorithmException exception) {
                        throw new IllegalStateException("Unable to generate MFA secret", exception);
                    }
                    user.setMfaSecret(mfaSecretProtector.protect(secret));
                    userRepository.save(user);
                } else {
                    secret = mfaSecretProtector.unprotect(storedSecret);
                    migrateLegacySecret(user, storedSecret, secret);
                }

                return mfaClient.getQrCode(username, secret)
                        .orElse(MfaSetupResult.failure("No response from Security Brain"));
            })
            .orElseThrow(() -> new RuntimeException("User not found"));
    }

    public boolean confirmMfaSetup(String username, String code) {
        return userRepository.findByUsername(username)
                .map(user -> {
                    String storedSecret = user.getMfaSecret();
                    if (storedSecret == null || storedSecret.isBlank()) {
                        return false;
                    }
                    String secret = mfaSecretProtector.unprotect(storedSecret);
                    if (!verifyTotp(secret, code)) {
                        return false;
                    }
                    if (!mfaSecretProtector.isProtected(storedSecret)) {
                        user.setMfaSecret(mfaSecretProtector.protect(secret));
                    }
                    user.setMfaEnabled(true);
                    userRepository.save(user);
                    return true;
                })
                .orElse(false);
    }
    
    public void registerUser(String username, String password) {
        if (userRepository.findByUsername(username).isPresent()) {
            log.warn("Registration rejected for existing username");
            throw new RuntimeException("Username already taken!");
        }

        String securedHash = passwordHasher.hash(password);

        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPasswordHash(securedHash); 

        userRepository.save(newUser);
        log.info("User registration succeeded");
    }

    public boolean verifyLogin(String username, String password) {
        return verifyLogin(username, password, null);
    }

    @Transactional
    public boolean verifyLogin(String username, String password, String mfaCode) {
        boolean verified = userRepository.findByUsernameForAuthentication(username)
            .map(user -> {
                if (loginAttemptPolicy.isLocked(user)) {
                    return false;
                }
                char[] passwordChars = password.toCharArray();
                boolean passwordValid;
                try {
                    passwordValid = passwordHasher.verify(user.getPasswordHash(), passwordChars);
                } finally {
                    Arrays.fill(passwordChars, '\0');
                }

                boolean loginValid = passwordValid;
                if (passwordValid && user.isMfaEnabled()) {
                    String storedSecret = user.getMfaSecret();
                    String secret;
                    try {
                        secret = mfaSecretProtector.unprotect(storedSecret);
                    } catch (IllegalStateException exception) {
                        log.error("MFA secret could not be decrypted for user {}", username);
                        loginValid = false;
                        secret = null;
                    }
                    if (secret != null) {
                        migrateLegacySecret(user, storedSecret, secret);
                        loginValid = verifyTotp(secret, mfaCode);
                    }
                }

                if (loginValid) {
                    loginAttemptPolicy.recordSuccess(user);
                } else {
                    loginAttemptPolicy.recordFailure(user);
                }
                userRepository.save(user);
                return loginValid;
            })
            .orElse(false);
        log.info("Login attempt completed with success={}", verified);
        return verified;
    }

    private boolean verifyTotp(String secret, String code) {
        if (secret == null || code == null || !code.matches("\\d{6}")) {
            return false;
        }
        try {
            return totpManager.verifyCode(totpManager.secretFromBase32(secret), Integer.parseInt(code));
        } catch (java.security.InvalidKeyException | NumberFormatException exception) {
            return false;
        }
    }

    private void migrateLegacySecret(User user, String storedSecret, String plaintextSecret) {
        if (!mfaSecretProtector.isProtected(storedSecret)) {
            user.setMfaSecret(mfaSecretProtector.protect(plaintextSecret));
            userRepository.save(user);
        }
    }
}
