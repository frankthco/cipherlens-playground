/**
 * signature.js – ECDSA Signature, SHA-256 Hashing, RSA Key Generation
 *
 * Cryptographic Algorithms Used:
 *   • ECDSA (secp256k1) with SHA-256 – digital signatures
 *   • SHA-256                         – cryptographic hashing
 *   • RSA-2048                        – asymmetric key generation
 *
 * PQC Impact:
 *   ECDSA (secp256k1) → CRITICAL
 *     Shor's algorithm breaks the Elliptic Curve Discrete Logarithm
 *     Problem, allowing private key recovery from a public key.
 *
 *   SHA-256 → MEDIUM
 *     Grover's algorithm provides a quadratic speedup for pre-image
 *     attacks (reducing effective security to 128-bit) and can accelerate
 *     collision search. Generally considered acceptable, but high-security
 *     applications should consider SHA-384 / SHA-512.
 *
 *   RSA-2048 → CRITICAL
 *     Shor's algorithm factors large integers in polynomial time,
 *     completely breaking RSA at any key size currently in use.
 */

const crypto = require("crypto");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ECDSA_CURVE = "secp256k1";
const HASH_ALGORITHM = "sha256";
const RSA_MODULUS_LENGTH = 2048;

// ---------------------------------------------------------------------------
// ECDSA Digital Signature (secp256k1 + SHA-256)
// ---------------------------------------------------------------------------

/**
 * Generate an ECDSA key pair on the secp256k1 curve.
 * @returns {{ publicKey: string, privateKey: string }} PEM-encoded key pair
 */
function generateEcdsaKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: ECDSA_CURVE,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

/**
 * Sign data using ECDSA (secp256k1) with SHA-256.
 *
 * @param {string|Buffer} data       – data to sign
 * @param {string}        privateKey – PEM-encoded EC private key
 * @returns {string} hex-encoded signature
 */
function signEcdsa(data, privateKey) {
  const sign = crypto.createSign(HASH_ALGORITHM);
  sign.update(data);
  sign.end();
  return sign.sign(privateKey, "hex");
}

/**
 * Verify an ECDSA (secp256k1 / SHA-256) signature.
 *
 * @param {string|Buffer} data      – original data
 * @param {string}        signature – hex-encoded signature
 * @param {string}        publicKey – PEM-encoded EC public key
 * @returns {boolean} true if valid
 */
function verifyEcdsa(data, signature, publicKey) {
  const verify = crypto.createVerify(HASH_ALGORITHM);
  verify.update(data);
  verify.end();
  return verify.verify(publicKey, signature, "hex");
}

// ---------------------------------------------------------------------------
// SHA-256 Hashing
// ---------------------------------------------------------------------------

/**
 * Compute the SHA-256 digest of the given data.
 *
 * @param {string|Buffer} data
 * @returns {string} hex-encoded hash
 */
function hashSha256(data) {
  return crypto.createHash(HASH_ALGORITHM).update(data).digest("hex");
}

// ---------------------------------------------------------------------------
// RSA-2048 Key Generation
// ---------------------------------------------------------------------------

/**
 * Generate a 2048-bit RSA key pair.
 * @returns {{ publicKey: string, privateKey: string }} PEM-encoded key pair
 */
function generateRsaKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: RSA_MODULUS_LENGTH,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  generateEcdsaKeyPair,
  signEcdsa,
  verifyEcdsa,
  hashSha256,
  generateRsaKeyPair,
};
