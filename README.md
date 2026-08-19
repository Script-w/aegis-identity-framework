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
* **Multi-Factor Authentication (MFA):** TOTP helpers and QR-code setup support Google Authenticator and Authy-compatible clients.
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

### 3. Launching the Services
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

## 📊 Legacy Scaling Vision 
Aegis follows the "Security by Design" philosophy. By decoupling the authentication engine from the threat analysis layer, the system is designed to scale horizontally. In a production environment, the Java core remains focused on low-latency throughput, while the Python layer can be scaled independently to handle complex security analytics.

​**Created by <a href="https://github.com/script-w"> Script w </a> as part of the Legacy Scaling Project..**