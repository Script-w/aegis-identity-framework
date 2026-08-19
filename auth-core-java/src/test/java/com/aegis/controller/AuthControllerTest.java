package com.aegis.controller;

import com.aegis.dto.RegistrationRequest;
import com.aegis.dto.LoginRequest;
import com.aegis.service.AuthService;
import com.aegis.security.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthControllerTest {
    @Test
    void registerDelegatesRequestAndReturnsSuccessMessage() {
        RecordingAuthService authService = new RecordingAuthService();
        AuthController controller = new AuthController(authService,
            new JwtService("test-secret-that-is-at-least-32-bytes-long", 3600000),
            "AEGIS_TOKEN", false);
        RegistrationRequest request = new RegistrationRequest();
        request.setUsername("alice");
        request.setPassword("password");

        ResponseEntity<String> response = controller.register(request);

        assertEquals("alice", authService.username);
        assertEquals("password", authService.password);
        assertEquals(200, response.getStatusCode().value());
        assertEquals("User registered successfully. Proceed to MFA enrollment.", response.getBody());
    }

    @Test
    void loginIssuesHttpOnlyCookieForValidCredentials() {
        RecordingAuthService authService = new RecordingAuthService();
        authService.loginResult = true;
        AuthController controller = new AuthController(authService,
                new JwtService("test-secret-that-is-at-least-32-bytes-long", 3600000),
                "AEGIS_TOKEN", false);
        LoginRequest request = new LoginRequest();
        request.setUsername("alice");
        request.setPassword("password");

        ResponseEntity<Void> response = controller.login(request);

        assertEquals(200, response.getStatusCode().value());
        String cookie = response.getHeaders().getFirst("Set-Cookie");
        assertNotNull(cookie);
        assertTrue(cookie.startsWith("AEGIS_TOKEN="));
        assertTrue(cookie.contains("HttpOnly"));
        assertTrue(cookie.contains("SameSite=Strict"));
        assertTrue(cookie.contains("Max-Age=3600"));
    }

    @Test
    void loginRejectsInvalidCredentials() {
        RecordingAuthService authService = new RecordingAuthService();
        AuthController controller = new AuthController(authService,
                new JwtService("test-secret-that-is-at-least-32-bytes-long", 3600000),
                "AEGIS_TOKEN", false);
        LoginRequest request = new LoginRequest();
        request.setUsername("alice");
        request.setPassword("wrong");

        assertEquals(401, controller.login(request).getStatusCode().value());
    }

    @Test
    void logoutExpiresAuthenticationCookie() {
        AuthController controller = new AuthController(new RecordingAuthService(),
                new JwtService("test-secret-that-is-at-least-32-bytes-long", 3600000),
                "AEGIS_TOKEN", false);

        String cookie = controller.logout().getHeaders().getFirst("Set-Cookie");

        assertNotNull(cookie);
        assertTrue(cookie.contains("Max-Age=0"));
        assertTrue(cookie.contains("HttpOnly"));
    }

    private static final class RecordingAuthService extends AuthService {
        private String username;
        private String password;
        private boolean loginResult;

        private RecordingAuthService() {
            super(null, null, null, null);
        }

        @Override
        public void registerUser(String username, String password) {
            this.username = username;
            this.password = password;
        }

        @Override
        public boolean verifyLogin(String username, String password, String mfaCode) {
            return loginResult;
        }
    }
}
