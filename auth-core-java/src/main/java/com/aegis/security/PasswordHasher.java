package com.aegis.security;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

/**
 * Argon2id password hasher utility.
 * - Stores/returns encoded Argon2 string (contains salt and params).
 * - Zeroes password char[] after use.
 * - Tune ITERATIONS / MEMORY_KIB / PARALLELISM to your deployment.
 */
public final class PasswordHasher {

    // Recommended defaults — tune to your environment
    private static final int ITERATIONS = 3;
    private static final int MEMORY_KIB = 64 * 1024; // 64 MiB
    private static final int PARALLELISM = 1;

    private final Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

    /**
     * Hashes the provided password and returns the encoded Argon2 string.
     *
     * @param password password chars (will be zeroed)
     * @return encoded Argon2 hash (store in DB)
     */
    public String hash(char[] password) {
        try {
            return argon2.hash(ITERATIONS, MEMORY_KIB, PARALLELISM, password.toCharArray());
        } finally {
            wipe(password);
        }
    }

    /**
     * Verifies provided password against the encoded Argon2 hash.
     *
     * @param encodedHash encoded Argon2 hash from DB
     * @param password    password chars (will be zeroed)
     * @return true if matches
     */
    public boolean verify(String encodedHash, char[] password) {
        try {
            return argon2.verify(encodedHash, password.toCharArray());
        } finally {
            wipe(password);
        }
    }

    private void wipe(char[] c) {
        if (c != null) {
            java.util.Arrays.fill(c, '\0');
        }
    }
}
