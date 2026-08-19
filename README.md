# Aegis Identity Framework
**A Security-First Identity Provider (IdP) for Scalable Legacy Systems.**

Aegis is a high-performance, distributed identity management system designed to secure modern web applications. It leverages a dual-service architecture to separate core identity logic from security intelligence and threat detection.

---

## 🚀 Architectural Framework
The system is built as a monorepo containing two primary microservices:

* **auth-core-java (Spring Boot 3.x):** The "Engine." Handles registration, Argon2id password hashing, JWT authentication in an HttpOnly cookie, and MFA QR-code coordination.
* **security-brain-python (FastAPI):** The "Intelligence." Generates MFA QR codes and verifies TOTP codes.
* **Database (PostgreSQL):** Stores user identities and MFA state. PostgreSQL can run locally through Docker Compose or remotely through Supabase.

---

## 🛡️ Security Features
* **Argon2id Hashing:** Implemented via `argon2-jvm` to provide resistance against GPU/ASIC cracking attacks.
* **Stateless JWT Auth:** Signed JWTs are issued in an `HttpOnly`, `SameSite=Strict` cookie after successful login.
* **Multi-Factor Authentication (MFA):** Per-user Base32 TOTP enrollment, QR-code setup, enrollment confirmation, and MFA-required login support Google Authenticator and Authy-compatible clients.
* **Protected MFA Secrets:** TOTP seeds are stored as authenticated AES-256-GCM envelopes and are decrypted only when needed for enrollment or verification.
* **Account Lockout:** Five consecutive password or MFA failures lock the account for 15 minutes; both values are configurable.
* **Authentication Event Logging:** Registration and login outcomes are recorded through the application logger; durable audit tables are not currently included.
* **Database Hardening:** User IDs use PostgreSQL UUIDs generated with `pgcrypto` to reduce predictable ID enumeration.

---

## 🛠️ Tech Stack
* **Languages:** Java 25, Python 3.11
* **Frameworks:** Spring Boot 3, Spring Security 6, FastAPI
* **Database:** PostgreSQL (Hosted on Supabase)
* **Runtime:** Docker Compose, with optional GitHub Codespaces support

---

## 📦 Getting Started

### 1. Database Setup
1.  For local development, copy `.env.example` to `.env`, replace the placeholder secrets, and run `docker compose up --build`.
2.  For Supabase, create a project and run [db/init.sql](db/init.sql) in the SQL Editor.

### 2. Environment Configuration
Set the following environment variables in `.env` or your deployment secret store:
* `DB_URL`: JDBC connection string (Port 6543 recommended).
* `DB_USER`: Database username.
* `DB_PASSWORD`: Database password.
* `JWT_SECRET`: at least 32 bytes for signing authentication tokens.
* `JWT_EXPIRATION`: token lifetime in milliseconds; defaults to one hour.
* `MFA_ENCRYPTION_KEY`: a Base64-encoded 32-byte key used only for MFA-secret encryption. Generate and store it independently from `JWT_SECRET`; changing it requires a deliberate key-rotation migration.
* `AUTH_LOCKOUT_MAX_ATTEMPTS` and `AUTH_LOCKOUT_DURATION_SECONDS`: account lockout threshold and duration; defaults are five attempts and 900 seconds.

### 3. Launching the Services

The default Docker Compose setup runs the Java service, Python service, and PostgreSQL locally. Inside Compose, the database is reached as `aegis-db`; do not use `localhost` for the Java container's database URL.

**Java Backend:**
```bash
cd auth-core-java
./mvnw spring-boot:run
```
 
**Python Security Service:**
```bash
cd security-brain-python
pip install -r requirements.txt
python main.py
 ```

The Python command starts Uvicorn on port 8000. Docker Compose starts both services and PostgreSQL together.

To run the full container integration flow, start the stack with `docker compose up --build --wait`, install `integration-tests/requirements.txt`, and run `python -m pytest integration-tests -v`. The test covers registration, password login, MFA enrollment and confirmation, and MFA-required login.

### Authentication Flow

1. Fetch `GET /api/auth/csrf`, retain its `XSRF-TOKEN` cookie, and send that token in the `X-XSRF-TOKEN` header on every subsequent `POST` request.
2. Register with `POST /api/auth/register`.
3. Log in with `POST /api/auth/login` using the username and password. The response sets an HttpOnly JWT cookie.
4. While authenticated, call `GET /api/auth/mfa/setup` to receive the QR-code payload.
5. Submit the six-digit authenticator code to `POST /api/auth/mfa/confirm` to enable MFA.
6. Future logins must include `mfaCode` in the login request before a JWT cookie is issued.

## 📊 Legacy Scaling Vision 
Aegis follows the "Security by Design" philosophy. By decoupling the authentication engine from the threat analysis layer, the system is designed to scale horizontally. In a production environment, the Java core remains focused on low-latency throughput, while the Python layer can be scaled independently to handle complex security analytics.

​**Created by <a href="https://github.com/script-w"> Script w </a> as part of the Legacy Scaling Project..**
