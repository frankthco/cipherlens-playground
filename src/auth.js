/**
 * auth.js – Password Hashing & Custom JWT Signing
 *
 * Cryptographic Algorithms Used:
 *   • bcrypt (10 salt rounds)          – password hashing
 *   • RS256  (RSA-2048 private key)    – JWT signing / verification
 *
 * PQC Impact:
 *   bcrypt  → SAFE   (symmetric / hash-based, resistant to Shor's algorithm)
 *   RS256   → CRITICAL (RSA-2048 broken by Shor's algorithm on a CRQC)
 */

const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BCRYPT_SALT_ROUNDS = 10;
const JWT_ALGORITHM = "RS256"; // RSA PKCS#1 v1.5 with SHA-256
const JWT_EXPIRATION = "1h";

// ---------------------------------------------------------------------------
// RSA-2048 Key Pair (generated once at module load for demo purposes)
// ---------------------------------------------------------------------------

const { privateKey: RSA_PRIVATE_KEY, publicKey: RSA_PUBLIC_KEY } =
  crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

// ---------------------------------------------------------------------------
// Password Hashing
// ---------------------------------------------------------------------------

/**
 * Hash a plaintext password using bcrypt with 10 salt rounds.
 * @param {string} plaintext
 * @returns {Promise<string>} bcrypt hash
 */
async function hashPassword(plaintext) {
  return bcrypt.hash(plaintext, BCRYPT_SALT_ROUNDS);
}

/**
 * Compare a plaintext password against a stored bcrypt hash.
 * @param {string} plaintext
 * @param {string} hash
 * @returns {Promise<boolean>}
 */
async function verifyPassword(plaintext, hash) {
  return bcrypt.compare(plaintext, hash);
}

// ---------------------------------------------------------------------------
// JWT Signing & Verification (RS256 – RSA-2048)
// ---------------------------------------------------------------------------

/**
 * Sign a JWT payload using RS256 with the RSA-2048 private key.
 * @param {object} payload – claims to embed in the token
 * @returns {string} signed JWT
 */
function signJwt(payload) {
  return jwt.sign(payload, RSA_PRIVATE_KEY, {
    algorithm: JWT_ALGORITHM,
    expiresIn: JWT_EXPIRATION,
  });
}

/**
 * Verify a JWT using RS256 with the RSA-2048 public key.
 * @param {string} token
 * @returns {object} decoded payload
 * @throws {JsonWebTokenError} if verification fails
 */
function verifyJwt(token) {
  return jwt.verify(token, RSA_PUBLIC_KEY, {
    algorithms: [JWT_ALGORITHM],
  });
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  hashPassword,
  verifyPassword,
  signJwt,
  verifyJwt,
  RSA_PUBLIC_KEY,
};
