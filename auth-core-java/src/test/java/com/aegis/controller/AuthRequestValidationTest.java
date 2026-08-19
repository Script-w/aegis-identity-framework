package com.aegis.controller;

import com.aegis.security.JwtService;
import com.aegis.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import java.util.Objects;

import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AuthRequestValidationTest {
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.afterPropertiesSet();
        AuthController controller = new AuthController(
                mock(AuthService.class),
                new JwtService("test-secret-that-is-at-least-32-bytes-long", 3600000),
                "AEGIS_TOKEN",
                false
        );
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setValidator(validator)
                .build();
    }

    @Test
    void registrationRejectsMissingFields() throws Exception {
        assertBadRequest("/api/auth/register", "{}");
    }

    @Test
    void registrationRejectsInvalidUsernameAndShortPassword() throws Exception {
        assertBadRequest("/api/auth/register",
                "{\"username\":\"not valid!\",\"password\":\"short\"}");
    }

    @Test
    void loginRejectsMissingPassword() throws Exception {
        assertBadRequest("/api/auth/login", "{\"username\":\"alice\"}");
    }

    @Test
    void loginRejectsNonNumericMfaCode() throws Exception {
        assertBadRequest("/api/auth/login",
                "{\"username\":\"alice\",\"password\":\"password\",\"mfaCode\":\"ABC123\"}");
    }

    @Test
    void mfaConfirmationRejectsMissingCode() throws Exception {
        assertBadRequest("/api/auth/mfa/confirm", "{}");
    }

    private void assertBadRequest(String path, String body) throws Exception {
        mockMvc.perform(post(Objects.requireNonNull(path))
                        .contentType(Objects.requireNonNull(MediaType.APPLICATION_JSON))
                        .content(Objects.requireNonNull(body)))
                .andExpect(status().isBadRequest());
    }
}
