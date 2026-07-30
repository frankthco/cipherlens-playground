/**
 * app.js – Express Application Entry Point
 *
 * Wires all cryptographic modules into REST endpoints for CipherLens
 * demonstration purposes.
 *
 * Endpoints:
 *   POST /api/login        → bcrypt password verify + RS256 JWT issuance
 *   POST /api/verify-okta  → Okta SSO access-token verification (RS256/ES256)
 *   POST /api/encrypt      → AES-256-GCM encryption + ECDH key exchange demo
 *   POST /api/sign         → ECDSA (secp256k1) signature + SHA-256 hash
 */

const path = require("path");
const express = require("express");
const { hashPassword, verifyPassword, signJwt, verifyJwt, RSA_PUBLIC_KEY } = require("./auth");
const { verifyOktaAccessToken } = require("./okta");
const {
  encryptAesGcm,
  decryptAesGcm,
  generateAesKey,
  generateEcdhKeyPair,
  deriveSharedSecret,
} = require("./crypto");
const {
  generateEcdsaKeyPair,
  signEcdsa,
  verifyEcdsa,
  hashSha256,
  generateRsaKeyPair,
} = require("./signature");

// ---------------------------------------------------------------------------
// App Setup
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// In-memory user store (demo only)
// ---------------------------------------------------------------------------

const users = {};

// ---------------------------------------------------------------------------
// POST /api/login
// ---------------------------------------------------------------------------

/**
 * Simulates user registration (first call) and login (subsequent calls).
 *
 * Crypto used:
 *   • bcrypt  – hash / verify password                     [SAFE]
 *   • RS256   – sign JWT with RSA-2048 private key          [CRITICAL]
 *
 * Request body: { "username": "alice", "password": "s3cret!" }
 * Response:     { "token": "<JWT>", "algorithm": "RS256" }
 */
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "username and password are required" });
    }

    // Register on first login attempt
    if (!users[username]) {
      const hashedPassword = await hashPassword(password);
      users[username] = { hashedPassword };
    }

    // Verify password
    const valid = await verifyPassword(password, users[username].hashedPassword);
    if (!valid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Issue JWT signed with RS256 (RSA-2048) — quantum-vulnerable
    const token = signJwt({ sub: username, role: "user" });

    return res.json({
      message: "Login successful",
      token,
      algorithm: "RS256 (RSA-2048)",
      pqcWarning: "JWT signed with RSA-2048 — vulnerable to Shor's algorithm",
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// POST /api/verify-okta
// ---------------------------------------------------------------------------

/**
 * Verifies an Okta-issued access token using the Okta JWKS endpoint.
 *
 * Crypto used:
 *   • RS256 / ES256 via Okta JWKS – verify JWT signature   [CRITICAL]
 *
 * Request body: { "accessToken": "<Okta Bearer Token>" }
 */
app.post("/api/verify-okta", async (req, res) => {
  try {
    const { accessToken } = req.body;

    if (!accessToken) {
      return res.status(400).json({ error: "accessToken is required" });
    }

    const jwt = await verifyOktaAccessToken(accessToken);

    return res.json({
      message: "Okta token verified",
      claims: jwt.claims,
      pqcWarning:
        "Okta JWKS uses RS256/ES256 — IdP public keys are vulnerable to Shor's algorithm",
    });
  } catch (err) {
    return res.status(401).json({ error: `Okta verification failed: ${err.message}` });
  }
});

// ---------------------------------------------------------------------------
// POST /api/encrypt
// ---------------------------------------------------------------------------

/**
 * Demonstrates AES-256-GCM encryption and ECDH key exchange.
 *
 * Crypto used:
 *   • AES-256-GCM – symmetric encryption                   [SAFE / LOW]
 *   • ECDH P-256  – key agreement                           [CRITICAL]
 *
 * Request body: { "plaintext": "sensitive data" }
 */
app.post("/api/encrypt", (req, res) => {
  try {
    const { plaintext } = req.body;

    if (!plaintext) {
      return res.status(400).json({ error: "plaintext is required" });
    }

    // ---- ECDH Key Exchange (P-256) ----
    const alice = generateEcdhKeyPair();
    const bob = generateEcdhKeyPair();

    const aliceSecret = deriveSharedSecret(alice.ecdh, bob.publicKey);
    const bobSecret = deriveSharedSecret(bob.ecdh, alice.publicKey);

    // Both sides derive the same shared secret
    const sharedKeyMatch = aliceSecret.equals(bobSecret);

    // Use first 32 bytes of the shared secret as the AES key (demo only —
    // in production, pass through a proper KDF like HKDF)
    const aesKey = aliceSecret.subarray(0, 32);

    // ---- AES-256-GCM Encryption ----
    const encrypted = encryptAesGcm(plaintext, aesKey);
    const decrypted = decryptAesGcm(encrypted, aesKey);

    return res.json({
      ecdhKeyExchange: {
        curve: "prime256v1 (P-256)",
        alicePublicKey: alice.publicKey,
        bobPublicKey: bob.publicKey,
        sharedSecretMatch: sharedKeyMatch,
        pqcWarning: "ECDH P-256 — vulnerable to Shor's algorithm & SNDL attacks",
      },
      aesEncryption: {
        algorithm: "AES-256-GCM",
        iv: encrypted.iv,
        ciphertext: encrypted.ciphertext,
        authTag: encrypted.authTag,
        decryptedVerification: decrypted,
        pqcStatus: "SAFE — Grover's reduces to 128-bit, still sufficient",
      },
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// POST /api/sign
// ---------------------------------------------------------------------------

/**
 * Demonstrates ECDSA digital signature, SHA-256 hashing, and RSA key gen.
 *
 * Crypto used:
 *   • ECDSA (secp256k1) + SHA-256 – digital signature      [CRITICAL]
 *   • SHA-256                      – hashing                [MEDIUM]
 *   • RSA-2048                     – key generation         [CRITICAL]
 *
 * Request body: { "message": "data to sign" }
 */
app.post("/api/sign", (req, res) => {
  try {
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({ error: "message is required" });
    }

    // ---- SHA-256 Hash ----
    const hash = hashSha256(message);

    // ---- ECDSA Signature (secp256k1) ----
    const ecKeyPair = generateEcdsaKeyPair();
    const signature = signEcdsa(message, ecKeyPair.privateKey);
    const signatureValid = verifyEcdsa(message, signature, ecKeyPair.publicKey);

    // ---- RSA-2048 Key Generation (demo) ----
    const rsaKeyPair = generateRsaKeyPair();

    return res.json({
      sha256: {
        algorithm: "SHA-256",
        hash,
        pqcStatus: "MEDIUM — Grover's halves effective bits; consider SHA-384/512",
      },
      ecdsaSignature: {
        curve: "secp256k1",
        hashAlgorithm: "SHA-256",
        signature,
        verified: signatureValid,
        pqcWarning: "ECDSA — vulnerable to Shor's algorithm",
      },
      rsaKeyGen: {
        algorithm: "RSA-2048",
        publicKeyPreview: rsaKeyPair.publicKey.substring(0, 120) + "...",
        pqcWarning: "RSA-2048 — factorable by Shor's algorithm on a CRQC",
      },
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// Health Check
// ---------------------------------------------------------------------------

app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ---------------------------------------------------------------------------
// Start Server
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`\n🔐 CipherLens running on http://localhost:${PORT}`);
  console.log("──────────────────────────────────────────────────");
  console.log("Endpoints:");
  console.log("  POST /api/login        – bcrypt + RS256 JWT");
  console.log("  POST /api/verify-okta  – Okta SSO (RS256/ES256)");
  console.log("  POST /api/encrypt      – AES-256-GCM + ECDH P-256");
  console.log("  POST /api/sign         – ECDSA + SHA-256 + RSA KeyGen");
  console.log("  GET  /health           – Health check");
  console.log("──────────────────────────────────────────────────\n");
});
