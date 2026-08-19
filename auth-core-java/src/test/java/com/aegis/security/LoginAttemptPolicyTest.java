package com.aegis.security;

import com.aegis.model.User;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoginAttemptPolicyTest {
    private static final Instant NOW = Instant.parse("2026-08-19T12:00:00Z");

    @Test
    void locksAtConfiguredFailureThreshold() {
        User user = new User();
        LoginAttemptPolicy policy = policyAt(NOW);

        policy.recordFailure(user);
        policy.recordFailure(user);
        assertFalse(policy.isLocked(user));
        policy.recordFailure(user);

        assertTrue(policy.isLocked(user));
        assertNotNull(user.getLockedUntil());
        assertEquals(3, user.getFailedLoginAttempts());
    }

    @Test
    void expiredLockIsCleared() {
        User user = new User();
        user.setFailedLoginAttempts(3);
        user.setLockedUntil(NOW.plus(Duration.ofMinutes(5)));

        assertFalse(policyAt(NOW.plus(Duration.ofMinutes(6))).isLocked(user));
        assertEquals(0, user.getFailedLoginAttempts());
        assertNull(user.getLockedUntil());
    }

    @Test
    void successfulLoginClearsFailures() {
        User user = new User();
        user.setFailedLoginAttempts(2);

        policyAt(NOW).recordSuccess(user);

        assertEquals(0, user.getFailedLoginAttempts());
        assertNull(user.getLockedUntil());
    }

    private LoginAttemptPolicy policyAt(Instant instant) {
        return new LoginAttemptPolicy(
                3,
                Duration.ofMinutes(5),
                Clock.fixed(instant, ZoneOffset.UTC)
        );
    }
}
