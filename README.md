# Aegis Identity Framework
**A Security-First Identity Provider (IdP) for Scalable Legacy Systems.**

Aegis is a high-performance, distributed identity management system designed to secure modern web applications. It leverages a dual-service architecture to separate core identity logic from security intelligence and threat detection.

---

## 🚀 Architectural Framework
The system is built as a monorepo containing two primary microservices:

* **auth-core-java (Spring Boot 3.x):** The "Engine." Handles high-concurrency authentication, Argon2id hashing, and JWT issuance.
* **security-brain-python (FastAPI):** The "Intelligence." Manages MFA (TOTP), IP-based threat detection, and advanced audit logging.
* **Database (Supabase/PostgreSQL):** A cloud-native relational store for user identities and audit trails.

---

## 🛡️ Security Features
* **Argon2id Hashing:** Implemented via `argon2-jvm` to provide resistance against GPU/ASIC cracking attacks.
* **Stateless JWT Auth:** Secure `HttpOnly` cookie-based token management allowing for horizontal scaling.
* **Multi-Factor Authentication (MFA):** Native TOTP support for Google Authenticator and Authy.
* **Zero-Trust Logging:** Comprehensive audit trails recording every authentication event (Success, Failure, MFA).
* **Database Hardening:** Uses UUIDs (v4) to prevent ID enumeration and IP-address-specific network logging.

---

## 🛠️ Tech Stack
* **Languages:** Java 17, Python 3.11
* **Frameworks:** Spring Boot 3, Spring Security 6, FastAPI
* **Database:** PostgreSQL (Hosted on Supabase)
* **Infrastructure:** GitHub Codespaces (Dev Containers)

---

## 📦 Getting Started

### 1. Database Setup
1.  Create a project on [Supabase](https://supabase.com).
2.  Run the initialization script found in `infrastructure/init.sql` in the Supabase SQL Editor.

### 2. Environment Configuration
Set the following environment variables in your GitHub Codespaces Secrets:
* `DB_URL`: JDBC connection string (Port 6543 recommended).
* `DB_USERNAME`: Database username.
* `DB_PASSWORD`: Database password.

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