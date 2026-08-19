package com.aegis.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class MfaClientTest {
    private HttpServer server;
    private MfaClient mfaClient;
    private final AtomicInteger requests = new AtomicInteger();
    private volatile String receivedBody;
    private volatile String receivedContentType;
    private volatile int responseStatus;
    private volatile String responseBody;

    @BeforeEach
    void setUp() throws Exception {
        responseStatus = 200;
        responseBody = "{\"data\":{\"qr_code\":\"qr-data\"}}";
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/mfa/setup", exchange -> {
            requests.incrementAndGet();
            receivedContentType = exchange.getRequestHeaders().getFirst("Content-Type");
            receivedBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(responseStatus, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        mfaClient = new MfaClient(new ObjectMapper(),
                "http://127.0.0.1:" + server.getAddress().getPort());
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    @Test
    void getQrCodeReturnsSuccessResponseAndSendsJsonBody() {
        Optional<MfaClient.MfaSetupResult> result = mfaClient.getQrCode("alice", "secret");

        assertTrue(result.isPresent());
        assertTrue(result.get().isSuccess());
        assertEquals("qr-data", result.get().getQrCode());
        assertEquals(1, requests.get());
        assertEquals("application/json", receivedContentType);
        assertEquals("{\"username\":\"alice\",\"secret\":\"secret\"}", receivedBody);
    }

    @Test
    void getQrCodeRejectsBlankUsername() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> mfaClient.getQrCode(" ", "secret"));

        assertEquals("username must not be blank", exception.getMessage());
        assertEquals(0, requests.get());
    }

    @Test
    void getQrCodeReturnsFailureForEmptyBody() {
        responseBody = "null";

        MfaClient.MfaSetupResult result = mfaClient.getQrCode("alice", "secret").orElseThrow();

        assertFalse(result.isSuccess());
        assertEquals("Empty response", result.getError());
    }

    @Test
    void getQrCodeReturnsFailureForHttpError() {
        responseStatus = 502;
        responseBody = "upstream failure";

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
}
