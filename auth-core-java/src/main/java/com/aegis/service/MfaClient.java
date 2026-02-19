package com.aegis.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Objects;
import java.util.Optional;

@Service
public class MfaClient {

    private static final Logger log = LoggerFactory.getLogger(MfaClient.class);
    private final RestTemplate restTemplate;
    
    // This value is injected from .env file via application.properties
    @Value("${aegis.security.brain-url}")
    private String securityBrainUrl;

    public MfaClient(RestTemplate restTemplate, @Value("${aegis.security.brain-url}") String securityBrainUrl) {
        this.restTemplate = restTemplate;
        this.securityBrainUrl = securityBrainUrl;
    }

    public Optional<MfaSetupResult> getQrCode(String username, String secret) {
        validateInput(username, "username");
        validateInput(secret, "secret");

        String endpoint = UriComponentsBuilder.fromHttpUrl(securityBrainUrl)
                .path("/mfa/setup")
                .build()
                .toUriString();

        MfaSetupRequest payload = new MfaSetupRequest(username, secret);

        try {
            ResponseEntity<MfaSetupResponse> response = restTemplate.postForEntity(endpoint, new HttpEntity<>(payload), MfaSetupResponse.class);
            MfaSetupResponse body = response.getBody();

            if (body == null) {
                log.warn("Security Brain returned empty body for user {}", username);
                return Optional.of(MfaSetupResult.failure("Empty response"));
            }

            if (!StringUtils.hasText(body.qrCode)) {
                log.warn("Security Brain response missing qrCode for user {}: {}", username, body.message);
                return Optional.of(MfaSetupResult.failure(body.message));
            }

            return Optional.of(MfaSetupResult.success(body.qrCode));
        } catch (RestClientResponseException e) {
            log.error("Security Brain call failed with status {} for user {}: {}", e.getRawStatusCode(), username, e.getResponseBodyAsString(), e);
            return Optional.of(MfaSetupResult.failure("Security Brain error: " + e.getRawStatusCode()));
        } catch (Exception e) {
            log.error("Security Brain call failed for user {}", username, e);
            return Optional.of(MfaSetupResult.failure("Unable to reach Security Brain"));
        }
    }

    private void validateInput(String value, String field) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }

    public static final class MfaSetupRequest {
        private final String username;
        private final String secret;

        public MfaSetupRequest(String username, String secret) {
            this.username = username;
            this.secret = secret;
        }

        public String getUsername() {
            return username;
        }

        public String getSecret() {
            return secret;
        }
    }

    public static final class MfaSetupResponse {
        private String message;
        private String qrCode;

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public String getQrCode() {
            return qrCode;
        }

        public void setQrCode(String qrCode) {
            this.qrCode = qrCode;
        }
    }

    public static final class MfaSetupResult {
        private final boolean success;
        private final String qrCode;
        private final String error;

        private MfaSetupResult(boolean success, String qrCode, String error) {
            this.success = success;
            this.qrCode = qrCode;
            this.error = error;
        }

        public static MfaSetupResult success(String qrCode) {
            return new MfaSetupResult(true, qrCode, null);
        }

        public static MfaSetupResult failure(String error) {
            return new MfaSetupResult(false, null, Objects.requireNonNullElse(error, "Unknown error"));
        }

        public boolean isSuccess() {
            return success;
        }

        public String getQrCode() {
            return qrCode;
        }

        public String getError() {
            return error;
        }
    }
}
