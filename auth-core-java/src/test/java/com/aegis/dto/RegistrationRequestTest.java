package com.aegis.dto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RegistrationRequestTest {
    @Test
    void accessorsRoundTripCredentials() {
        RegistrationRequest request = new RegistrationRequest();

        request.setUsername("alice");
        request.setPassword("password");

        assertEquals("alice", request.getUsername());
        assertEquals("password", request.getPassword());
    }
}
