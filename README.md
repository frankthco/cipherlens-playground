# 🔐 CipherLens — Post-Quantum Cryptography Readiness Assessment

A **Node.js / Express** proof-of-concept application that deliberately uses classical cryptographic algorithms to demonstrate **CipherLens** capabilities for **Quantum Readiness Assessment**.

The application implements common real-world cryptographic patterns — password hashing, JWT authentication, Okta SSO integration, symmetric encryption, key exchange, and digital signatures — so that CipherLens can produce a **Cryptographic Bill of Materials (CBOM)** and flag quantum-vulnerable components.

---

## 📂 Project Structure

```
cipherlens-demo-app/
├── src/
│   ├── auth.js          # Password Hashing (bcrypt) & JWT Signing (RS256)
│   ├── okta.js          # Okta SSO Token Verification (RS256/ES256 JWKS)
│   ├── crypto.js        # AES-256-GCM Encryption & ECDH Key Exchange (P-256)
│   ├── signature.js     # ECDSA Signature (secp256k1), SHA-256, RSA-2048 KeyGen
│   └── app.js           # Express entry point — wires all endpoints
├── package.json
└── README.md            # ← You are here
```

---

## 🚀 Quick Start

### Prerequisites

- **Node.js** ≥ 18.x
- **npm** ≥ 9.x

### Install & Run

```bash
# Install dependencies
npm install

# Start the server
npm start

# Or, with auto-reload during development (Node.js ≥ 18.11)
npm run dev
```

The server starts on `http://localhost:3000`.

### 🔐 Auth0 (Okta CIC) Setup (For Real SSO Demo)

To test the end-to-end SSO flow, you can connect this app to a free Auth0 (Okta CIC) Developer account:

1. Sign up at [auth0.com](https://auth0.com/)
2. In the Auth0 Dashboard, go to **Applications** → **Create Application**
3. Select **Single Page Web Applications**
4. Set the **Allowed Callback URLs**, **Allowed Logout URLs**, and **Allowed Web Origins** to `http://localhost:3000` (or your deployed Azure URL)
5. Copy your `.env.example` to `.env` and fill in the values:

```bash
cp .env.example .env
```

| Variable         | Example Value                                        | Description                  |
| :--------------- | :--------------------------------------------------- | :--------------------------- |
| `OKTA_ISSUER`    | `https://cypherlens.cic-demo-platform.auth0app.com/` | Your Auth0 domain URL          |
| `OKTA_CLIENT_ID` | `dnMH...`                                            | Your Auth0 SPA Client ID       |
| `PORT`           | `3000`                                               | HTTP listen port (Optional)    |

---

## 🔌 API Endpoints

### `POST /api/login` — Password Auth + JWT Issuance

```bash
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "s3cret!"}'
```

**Crypto used:** `bcrypt` (10 rounds) + `RS256` JWT (RSA-2048)

---

### `POST /api/verify-okta` — Okta SSO Token Verification

```bash
curl -X POST http://localhost:3000/api/verify-okta \
  -H "Content-Type: application/json" \
  -d '{"accessToken": "<OKTA_ACCESS_TOKEN>"}'
```

**Crypto used:** Okta JWKS — `RS256` / `ES256` signature verification

---

### `POST /api/encrypt` — AES-256-GCM + ECDH Key Exchange

```bash
curl -X POST http://localhost:3000/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "Top secret quantum data"}'
```

**Crypto used:** `AES-256-GCM` (symmetric) + `ECDH` (P-256 key agreement)

---

### `POST /api/sign` — ECDSA Signature + SHA-256 + RSA KeyGen

```bash
curl -X POST http://localhost:3000/api/sign \
  -H "Content-Type: application/json" \
  -d '{"message": "Sign this document"}'
```

**Crypto used:** `ECDSA` (secp256k1 + SHA-256), `SHA-256` hash, `RSA-2048` key generation

---

### `GET /health` — Health Check

```bash
curl http://localhost:3000/health
```

---

## 📊 PQC Assessment Report

### 1. CBOM & Static Analysis Mapping

The following table maps every cryptographic function in this application to its quantum risk level:

| Target File       | Crypto Function    | Algorithm / Parameters        | Vulnerable to Quantum Attack?                    | Risk Level   |
| :---------------- | :----------------- | :---------------------------- | :----------------------------------------------- | :----------- |
| `src/auth.js`     | Password Hash      | bcrypt (10 rounds)            | **No** — resistant to Shor's algorithm           | 🟢 **LOW**   |
| `src/auth.js`     | JWT Signing        | RS256 (RSA-2048)              | **Yes** — Shor's algorithm factors RSA modulus   | 🔴 **CRITICAL** |
| `src/okta.js`     | SSO Verification   | RS256 / ES256 (JWKS)          | **Yes** — Shor's algorithm on IdP public key     | 🔴 **CRITICAL** |
| `src/crypto.js`   | Data Encryption    | AES-256-GCM                   | **Low impact** — Grover's reduces to 128-bit     | 🟢 **SAFE / LOW** |
| `src/crypto.js`   | Key Exchange       | ECDH (P-256 / prime256v1)     | **Yes** — Shor's + Store Now, Decrypt Later      | 🔴 **CRITICAL** |
| `src/signature.js`| Digital Signature  | ECDSA (secp256k1) + SHA-256   | **Yes** — Shor's algorithm breaks ECDLP          | 🔴 **CRITICAL** |
| `src/signature.js`| Hash Function      | SHA-256                        | **Minor** — Grover's halves effective bits        | 🟡 **MEDIUM** |
| `src/signature.js`| Key Generation     | RSA-2048                       | **Yes** — Shor's algorithm factors RSA modulus   | 🔴 **CRITICAL** |

#### Summary

| Risk Level | Count | Percentage |
| :--------- | ----: | ---------: |
| 🔴 CRITICAL | 5     | 62.5%      |
| 🟡 MEDIUM   | 1     | 12.5%      |
| 🟢 LOW/SAFE | 2     | 25.0%      |

> **⚠️  Overall Quantum Readiness: HIGH RISK**
>
> 5 out of 8 cryptographic functions are critically vulnerable to quantum attack via Shor's algorithm. Immediate migration planning is recommended.

---

### 2. Quantum Impact & Migration Roadmap (NIST PQC Standards)

#### 🔴 Public-Key Cryptography (RSA / ECC) — **HIGH RISK**

| Current Algorithm            | Threat                               | NIST PQC Replacement                             | Standard    |
| :--------------------------- | :----------------------------------- | :------------------------------------------------ | :---------- |
| RSA-2048 (JWT / KeyGen)      | Shor's algorithm (integer factoring) | **ML-DSA** (Dilithium) for signatures             | FIPS 204    |
| ECDSA secp256k1 (signatures) | Shor's algorithm (ECDLP)            | **ML-DSA** (Dilithium) for signatures             | FIPS 204    |
| ECDH P-256 (key exchange)    | Shor's algorithm (ECDLP) + SNDL     | **ML-KEM** (Kyber) for key encapsulation          | FIPS 203    |

**Migration Actions:**
1. **Phase 1 — Hybrid Mode (Now → 2027):**
   - Deploy hybrid signatures: `RSA + ML-DSA` (dual-sign, verify both).
   - Deploy hybrid key exchange: `ECDH + ML-KEM` (combine shared secrets).
   - This provides backward compatibility while adding quantum resistance.

2. **Phase 2 — PQC-Only (2027 → 2030):**
   - Deprecate classical algorithms once ecosystem support matures.
   - Transition JWT signing to ML-DSA (when `jsonwebtoken` or equivalent libraries add support).
   - Replace ECDH with ML-KEM for all key agreements.

---

#### 🔴 SaaS / Okta SSO — **HIGH RISK**

| Component                      | Current State            | Quantum Threat                                    |
| :----------------------------- | :----------------------- | :------------------------------------------------ |
| Okta JWKS Endpoint             | RS256 / ES256 keys       | Shor's → forge tokens that pass verification      |
| `@okta/jwt-verifier` SDK       | Validates RSA/EC sigs    | Dependent on Okta's key infrastructure            |

**Migration Actions:**
1. **Monitor Okta's PQC roadmap** — Okta must publish ML-DSA / hybrid JWKS keys.
2. **Prepare for SDK updates** — Ensure the application can consume PQC-signed tokens when `@okta/jwt-verifier` adds support.
3. **Adopt Hybrid Signatures during transition** — Accept both classical and PQC-signed tokens simultaneously using a dual-verification approach.
4. **Shorten token lifetimes** — Reduce the window for "Store Now, Decrypt Later" attacks on bearer tokens.

---

#### 🟢 Symmetric Encryption (AES-256) — **LOW RISK**

| Current Algorithm | Quantum Impact                         | Action Required                        |
| :---------------- | :------------------------------------- | :------------------------------------- |
| AES-256-GCM       | Grover's → effective 128-bit security  | **Retain** — 128-bit quantum security is sufficient |

No migration needed. AES-256 already provides adequate post-quantum security.

---

#### 🟡 Hashing (SHA-256) — **MEDIUM RISK**

| Current Algorithm | Quantum Impact                                 | Action Required                                      |
| :---------------- | :--------------------------------------------- | :--------------------------------------------------- |
| SHA-256           | Grover's → pre-image reduced to 128-bit        | **Consider** upgrading to SHA-384 or SHA-512         |
| bcrypt            | Not affected by Shor's; quantum speedup minimal | **Consider** migrating to Argon2id for future-proofing |

**Migration Actions:**
1. Upgrade high-security hashing to **SHA-384** or **SHA-512** for additional quantum margin.
2. Evaluate migration from bcrypt to **Argon2id** (memory-hard, recommended by OWASP).

---

### 3. Recommended PQC Algorithm Mapping

```
┌─────────────────────────────────────────────────────────────────────┐
│                     PQC Migration Mapping                          │
├──────────────────────┬──────────────────────────────────────────────┤
│   Classical (Now)    │   Post-Quantum (Target)                     │
├──────────────────────┼──────────────────────────────────────────────┤
│ RSA-2048 (sign)      │ → ML-DSA-65  (FIPS 204 / Dilithium3)       │
│ ECDSA secp256k1      │ → ML-DSA-44  (FIPS 204 / Dilithium2)       │
│ ECDH P-256           │ → ML-KEM-768 (FIPS 203 / Kyber768)         │
│ RS256/ES256 (Okta)   │ → ML-DSA (pending IdP support)             │
│ AES-256-GCM          │ → AES-256-GCM (no change needed)           │
│ SHA-256              │ → SHA-384 / SHA-512 (recommended upgrade)   │
│ bcrypt               │ → Argon2id (recommended, not PQC-specific)  │
└──────────────────────┴──────────────────────────────────────────────┘
```

---

### 4. SNDL (Store Now, Decrypt Later) Risk Assessment

Certain data in this application is at risk of SNDL attacks, where adversaries capture encrypted traffic today and decrypt it once a cryptographically relevant quantum computer (CRQC) becomes available:

| Data Flow                          | SNDL Risk | Rationale                                                |
| :--------------------------------- | :-------- | :------------------------------------------------------- |
| ECDH key exchange (`/api/encrypt`) | 🔴 HIGH   | Captured DH handshake can be broken to recover AES key   |
| JWT tokens (`/api/login`)          | 🟡 MEDIUM | Tokens have short expiration; replay risk if private key recovered |
| AES-GCM ciphertext                 | 🟢 LOW    | Symmetric cipher not directly vulnerable; key exchange is the risk |
| Okta SSO tokens                    | 🟡 MEDIUM | Token forgery risk if Okta's signing key is compromised  |

---

## 📚 References

- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 — ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 — ML-DSA (Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST SP 1800-38C — Migration to PQC](https://csrc.nist.gov/publications/detail/sp/1800-38/draft)
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [Okta Security — Preparing for Post-Quantum](https://www.okta.com/blog/)

---

> This project was developed by **Pralaphat Wattanachai** for educational purposes.

## 📝 License

MIT
