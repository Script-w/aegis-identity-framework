package com.aegis.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;

@Service
public class MfaClient {

    private static final Logger log = LoggerFactory.getLogger(MfaClient.class);
    private final ObjectMapper objectMapper;
    private final String securityBrainUrl;

    public MfaClient(ObjectMapper objectMapper,
                     @Value("${aegis.security.brain-url}") String securityBrainUrl) {
        this.objectMapper = objectMapper;
        this.securityBrainUrl = securityBrainUrl;
    }

    public Optional<MfaSetupResult> getQrCode(String username, String secret) {
        validateInput(username, "username");
        validateInput(secret, "secret");

        String endpoint = UriComponentsBuilder.fromUriString(
                Objects.requireNonNull(securityBrainUrl, "securityBrainUrl"))
                .path("/mfa/setup")
                .build()
                .toUriString();

        MfaSetupRequest payload = new MfaSetupRequest(username, secret);

        try {
            String requestBody = objectMapper.writeValueAsString(payload);
            byte[] requestBytes = requestBody.getBytes(StandardCharsets.UTF_8);
            HttpURLConnection connection = (HttpURLConnection) URI.create(endpoint).toURL().openConnection();
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(3_000);
            connection.setReadTimeout(5_000);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setFixedLengthStreamingMode(requestBytes.length);
            try (var output = connection.getOutputStream()) {
                output.write(requestBytes);
            }

            int status = connection.getResponseCode();
            InputStream responseStream = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
            String responseText;
            try (responseStream) {
                responseText = responseStream == null
                        ? ""
                        : new String(responseStream.readAllBytes(), StandardCharsets.UTF_8);
            } finally {
                connection.disconnect();
            }

            if (status < 200 || status >= 300) {
                log.error("Security Brain call failed with status {} for user {}", status, username);
                return Optional.of(MfaSetupResult.failure("Security Brain error: " + status));
            }

            MfaSetupResponse body = responseText.isBlank()
                    ? null
                    : objectMapper.readValue(responseText, MfaSetupResponse.class);

            if (body == null) {
                log.warn("Security Brain returned empty body for user {}", username);
                return Optional.of(MfaSetupResult.failure("Empty response"));
            }

            String qr = body.getQrCode();
            if (!StringUtils.hasText(qr)) {
                log.warn("Security Brain response missing qrCode for user {}: {}", username, body.getMessage());
                return Optional.of(MfaSetupResult.failure(body.getMessage()));
            }

            return Optional.of(MfaSetupResult.success(qr));
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
        private Data data;

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public Data getData() {
            return data;
        }

        public void setData(Data data) {
            this.data = data;
        }

        public String getQrCode() {
            return data != null ? data.getQrCode() : null;
        }

        public static final class Data {
            @JsonProperty("qr_code")
            private String qrCode;

            public String getQrCode() {
                return qrCode;
            }

            public void setQrCode(String qrCode) {
                this.qrCode = qrCode;
            }
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
