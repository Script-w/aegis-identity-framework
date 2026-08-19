package com.aegis.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

class MfaClientTest {
    private StubRestTemplate restTemplate;
    private MfaClient mfaClient;

    @BeforeEach
    void setUp() {
        restTemplate = new StubRestTemplate();
        mfaClient = new MfaClient(restTemplate, "http://security-brain.test");
    }

    @Test
    void getQrCodeReturnsSuccessResponse() {
        MfaClient.MfaSetupResponse body = new MfaClient.MfaSetupResponse();
        MfaClient.MfaSetupResponse.Data data = new MfaClient.MfaSetupResponse.Data();
        data.setQrCode("qr-data");
        body.setData(data);
        restTemplate.response = () -> ResponseEntity.ok(body);

        Optional<MfaClient.MfaSetupResult> result = mfaClient.getQrCode("alice", "secret");

        assertTrue(result.isPresent());
        assertTrue(result.get().isSuccess());
        assertEquals("qr-data", result.get().getQrCode());
    }

    @Test
    void getQrCodeRejectsBlankUsername() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> mfaClient.getQrCode(" ", "secret"));

        assertEquals("username must not be blank", exception.getMessage());
        assertNull(restTemplate.response);
    }

    @Test
    void getQrCodeReturnsFailureForEmptyBody() {
        restTemplate.response = () -> ResponseEntity.ok(null);

        MfaClient.MfaSetupResult result = mfaClient.getQrCode("alice", "secret").orElseThrow();

        assertFalse(result.isSuccess());
        assertEquals("Empty response", result.getError());
    }

    @Test
    void getQrCodeReturnsFailureForHttpError() {
        RestClientResponseException exception = new RestClientResponseException(
                "bad gateway", 502, "Bad Gateway", null,
                "upstream failure".getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
        restTemplate.response = () -> {
            throw exception;
        };

        MfaClient.MfaSetupResult result = mfaClient.getQrCode("alice", "secret").orElseThrow();

        assertFalse(result.isSuccess());
        assertEquals("Security Brain error: 502", result.getError());
    }

    @Test
    void resultFactoryDefaultsNullFailureMessage() {
        MfaClient.MfaSetupResult result = MfaClient.MfaSetupResult.failure(null);

        assertFalse(result.isSuccess());
        assertEquals("Unknown error", result.getError());
    }

    private static final class StubRestTemplate extends RestTemplate {
        private Supplier<ResponseEntity<MfaClient.MfaSetupResponse>> response;

        @Override
        public <T> ResponseEntity<T> postForEntity(String url, Object request, Class<T> responseType,
                                                    Object... uriVariables) {
            @SuppressWarnings("unchecked")
            ResponseEntity<T> result = (ResponseEntity<T>) response.get();
            return result;
        }
    }
}
