package com.aegis.service;

import com.aegis.model.User;
import com.aegis.repository.UserRepository;
import com.aegis.security.PasswordHasher;
import com.aegis.security.MfaSecretProtector;
import com.aegis.security.LoginAttemptPolicy;
import com.aegis.security.TotpManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.Optional;
import java.time.Clock;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class AuthServiceTest {
    private static final String MFA_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    private RecordingUserRepository userRepository;
    private PasswordHasher passwordHasher;
    private StubMfaClient mfaClient;
    private TotpManager totpManager;
    private AuthService authService;

    @BeforeEach
    void setUp() throws Exception {
        userRepository = new RecordingUserRepository();
        passwordHasher = new PasswordHasher();
        mfaClient = new StubMfaClient();
        totpManager = new TotpManager();
        authService = new AuthService(userRepository.proxy, passwordHasher, mfaClient, totpManager,
                new MfaSecretProtector(MFA_KEY),
                new LoginAttemptPolicy(5, Duration.ofMinutes(15), Clock.systemUTC()));
    }

    @Test
    void registerUserHashesAndPersistsNewUser() {
        authService.registerUser("new-user", "password");

        assertEquals("new-user", userRepository.savedUser.getUsername());
        assertTrue(passwordHasher.verify(userRepository.savedUser.getPasswordHash(), "password".toCharArray()));
    }

    @Test
    void registerUserRejectsDuplicateUsername() {
        userRepository.user = new User();

        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> authService.registerUser("existing", "password"));

        assertEquals("Username already taken!", exception.getMessage());
        assertNull(userRepository.savedUser);
    }

    @Test
    void verifyLoginReturnsHasherResultForExistingUser() {
        User user = new User();
        user.setPasswordHash(passwordHasher.hash("password"));
        userRepository.user = user;

        assertTrue(authService.verifyLogin("user", "password"));
    }

    @Test
    void verifyLoginReturnsFalseForUnknownUser() {
        assertFalse(authService.verifyLogin("missing", "password"));
    }

    @Test
    void locksAccountAfterFiveFailedLogins() {
        User user = new User();
        user.setPasswordHash(passwordHasher.hash("password"));
        userRepository.user = user;

        for (int attempt = 0; attempt < 5; attempt++) {
            assertFalse(authService.verifyLogin("user", "wrong-password"));
        }

        assertNotNull(user.getLockedUntil());
        assertFalse(authService.verifyLogin("user", "password"));
    }

    @Test
    void verifyLoginRequiresMfaCodeWhenMfaIsEnabled() {
        User user = new User();
        user.setPasswordHash(passwordHasher.hash("password"));
        user.setMfaEnabled(true);
        user.setMfaSecret("JBSWY3DPEHPK3PXP");
        userRepository.user = user;

        assertFalse(authService.verifyLogin("user", "password", null));
        assertFalse(authService.verifyLogin("user", "password", "12345"));
    }

    @Test
    void confirmMfaSetupRejectsInvalidCode() {
        User user = new User();
        user.setMfaSecret("JBSWY3DPEHPK3PXP");
        userRepository.user = user;

        assertFalse(authService.confirmMfaSetup("user", "000000"));
        assertFalse(user.isMfaEnabled());
        assertNull(userRepository.savedUser);
    }

    @Test
    void initiateMfaSetupReturnsFailureWhenSecurityBrainIsUnavailable() {
        userRepository.user = new User();
        mfaClient.result = Optional.empty();

        AuthService.MfaEnrollmentResult result = authService.initiateMfaSetup("user");

        assertFalse(result.isSuccess());
        assertEquals("No response from Security Brain", result.getError());
        assertTrue(userRepository.savedUser.getMfaSecret().startsWith("v1:"));
        assertFalse(userRepository.savedUser.getMfaSecret().contains("JBSWY3DPEHPK3PXP"));
    }

    @Test
    void initiateMfaSetupReturnsManualKeyButStoresOnlyCiphertext() {
        userRepository.user = new User();
        mfaClient.result = Optional.of(MfaClient.MfaSetupResult.success("encoded-qr"));

        AuthService.MfaEnrollmentResult result = authService.initiateMfaSetup("user");

        assertTrue(result.isSuccess());
        assertEquals("encoded-qr", result.getQrCode());
        assertNotNull(result.getManualEntryKey());
        assertNotEquals(result.getManualEntryKey(), userRepository.savedUser.getMfaSecret());
        assertEquals(
                result.getManualEntryKey(),
                new MfaSecretProtector(MFA_KEY).unprotect(userRepository.savedUser.getMfaSecret())
        );
    }

    @Test
    void verifyLoginMigratesLegacyPlaintextMfaSecret() {
        User user = new User();
        user.setPasswordHash(passwordHasher.hash("password"));
        user.setMfaEnabled(true);
        user.setMfaSecret("JBSWY3DPEHPK3PXP");
        userRepository.user = user;

        authService.verifyLogin("user", "password", "000000");

        assertNotNull(userRepository.savedUser);
        assertTrue(userRepository.savedUser.getMfaSecret().startsWith("v1:"));
    }

    @Test
    void initiateMfaSetupRejectsUnknownUser() {
        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> authService.initiateMfaSetup("missing"));

        assertEquals("User not found", exception.getMessage());
    }

    private static final class RecordingUserRepository {
        private User user;
        private User savedUser;
        private final UserRepository proxy = (UserRepository) Proxy.newProxyInstance(
                UserRepository.class.getClassLoader(), new Class<?>[]{UserRepository.class},
                (object, method, args) -> {
                    if (method.getName().equals("findByUsername")
                            || method.getName().equals("findByUsernameForAuthentication")) {
                        return Optional.ofNullable(user);
                    }
                    if (method.getName().equals("save")) {
                        savedUser = (User) args[0];
                        return savedUser;
                    }
                    if (method.getName().equals("toString")) {
                        return "RecordingUserRepository";
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static final class StubMfaClient extends MfaClient {
        private Optional<MfaSetupResult> result = Optional.empty();

        private StubMfaClient() {
            super(new com.fasterxml.jackson.databind.ObjectMapper(), "http://unused");
        }

        @Override
        public Optional<MfaSetupResult> getQrCode(String username, String secret) {
            return result;
        }
    }
}
