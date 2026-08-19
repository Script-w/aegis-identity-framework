package com.aegis.model;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserTest {
    @Test
    void accessorsRoundTripEntityState() {
        User user = new User();
        UUID id = UUID.randomUUID();
        LocalDateTime createdAt = LocalDateTime.now();

        user.setId(id);
        user.setUsername("alice");
        user.setPasswordHash("hash");
        user.setMfaEnabled(true);
        user.setMfaSecret("secret");
        user.setCreatedAt(createdAt);

        assertEquals(id, user.getId());
        assertEquals("alice", user.getUsername());
        assertEquals("hash", user.getPasswordHash());
        assertTrue(user.isMfaEnabled());
        assertEquals("secret", user.getMfaSecret());
        assertEquals(createdAt, user.getCreatedAt());
    }

    @Test
    void newUserStartsWithMfaDisabled() {
        assertFalse(new User().isMfaEnabled());
    }
}
