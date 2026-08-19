package com.aegis.controller;

import com.aegis.dto.RegistrationRequest;
import com.aegis.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthControllerTest {
    @Test
    void registerDelegatesRequestAndReturnsSuccessMessage() {
        RecordingAuthService authService = new RecordingAuthService();
        AuthController controller = new AuthController(authService);
        RegistrationRequest request = new RegistrationRequest();
        request.setUsername("alice");
        request.setPassword("password");

        ResponseEntity<String> response = controller.register(request);

        assertEquals("alice", authService.username);
        assertEquals("password", authService.password);
        assertEquals(200, response.getStatusCode().value());
        assertEquals("User registered successfully. Proceed to MFA enrollment.", response.getBody());
    }

    private static final class RecordingAuthService extends AuthService {
        private String username;
        private String password;

        private RecordingAuthService() {
            super(null, null, null);
        }

        @Override
        public void registerUser(String username, String password) {
            this.username = username;
            this.password = password;
        }
    }
}
