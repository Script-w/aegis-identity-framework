-- Create the Aegis Schema
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    mfa_secret VARCHAR(255),  -- Base32 secret shared with Python Brain
    mfa_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Optional: Seed a test user (Password is 'password' - Argon2 hashed)
-- Note: Replace with a real hash later
INSERT INTO users (username, password_hash, mfa_enabled) 
VALUES ('admin', '$argon2id$v=19$m=65536,t=3,p=4$OGZ...example', false)
ON CONFLICT (username) DO NOTHING;