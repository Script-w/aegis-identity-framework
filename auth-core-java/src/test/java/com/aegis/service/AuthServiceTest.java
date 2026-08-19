package com.aegis.service;

import com.aegis.model.User;
import com.aegis.repository.UserRepository;
import com.aegis.security.PasswordHasher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class AuthServiceTest {
    private RecordingUserRepository userRepository;
    private PasswordHasher passwordHasher;
    private StubMfaClient mfaClient;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        userRepository = new RecordingUserRepository();
        passwordHasher = new PasswordHasher();
        mfaClient = new StubMfaClient();
        authService = new AuthService(userRepository.proxy, passwordHasher, mfaClient);
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
    void initiateMfaSetupReturnsFailureWhenSecurityBrainIsUnavailable() {
        userRepository.user = new User();
        mfaClient.result = Optional.empty();

        MfaClient.MfaSetupResult result = authService.initiateMfaSetup("user");

        assertFalse(result.isSuccess());
        assertEquals("No response from Security Brain", result.getError());
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
                    if (method.getName().equals("findByUsername")) {
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
            super(new org.springframework.web.client.RestTemplate(), "http://unused");
        }

        @Override
        public Optional<MfaSetupResult> getQrCode(String username, String secret) {
            return result;
        }
    }
}
