package com.aegis.security;

import com.aegis.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

@Component
public class LoginAttemptPolicy {
    private final int maxAttempts;
    private final Duration lockDuration;
    private final Clock clock;

    @Autowired
    public LoginAttemptPolicy(
            @Value("${auth.lockout.max-attempts:5}") int maxAttempts,
            @Value("${auth.lockout.duration-seconds:900}") long lockDurationSeconds) {
        this(maxAttempts, Duration.ofSeconds(lockDurationSeconds), Clock.systemUTC());
    }

    public LoginAttemptPolicy(int maxAttempts, Duration lockDuration, Clock clock) {
        if (maxAttempts < 1 || lockDuration.isNegative() || lockDuration.isZero()) {
            throw new IllegalArgumentException("Lockout policy values must be positive");
        }
        this.maxAttempts = maxAttempts;
        this.lockDuration = lockDuration;
        this.clock = clock;
    }

    public boolean isLocked(User user) {
        Instant lockedUntil = user.getLockedUntil();
        if (lockedUntil == null) {
            return false;
        }
        if (lockedUntil.isAfter(clock.instant())) {
            return true;
        }
        user.setLockedUntil(null);
        user.setFailedLoginAttempts(0);
        return false;
    }

    public void recordFailure(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);
        if (attempts >= maxAttempts) {
            user.setLockedUntil(clock.instant().plus(lockDuration));
        }
    }

    public void recordSuccess(User user) {
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
    }
}
