/**
 * crypto.js – Data Encryption (AES-GCM) & Key Exchange (ECDH)
 *
 * Cryptographic Algorithms Used:
 *   • AES-256-GCM              – symmetric authenticated encryption
 *   • ECDH (prime256v1 / P-256) – ephemeral key agreement
 *
 * PQC Impact:
 *   AES-256-GCM → SAFE / LOW
 *     Grover's algorithm reduces effective security to ~128-bit, which is
 *     still considered sufficient for the foreseeable future.
 *
 *   ECDH (P-256) → CRITICAL
 *     Shor's algorithm can solve the Elliptic Curve Discrete Logarithm
 *     Problem (ECDLP) in polynomial time, completely breaking ECDH key
 *     exchange. Additionally, any traffic captured today (Store Now,
 *     Decrypt Later) can be retroactively decrypted once a CRQC exists.
 */

const crypto = require("crypto");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AES_ALGORITHM = "aes-256-gcm";
const AES_KEY_LENGTH = 32; // 256 bits
const AES_IV_LENGTH = 12; // 96 bits (recommended for GCM)
const AES_AUTH_TAG_LENGTH = 16; // 128 bits

const ECDH_CURVE = "prime256v1"; // NIST P-256

// ---------------------------------------------------------------------------
// AES-256-GCM Encryption / Decryption
// ---------------------------------------------------------------------------

/**
 * Encrypt plaintext using AES-256-GCM.
 *
 * @param {string} plaintext – data to encrypt
 * @param {Buffer} key       – 256-bit encryption key
 * @returns {{ iv: string, ciphertext: string, authTag: string }}
 *   All values are hex-encoded for easy transport.
 */
function encryptAesGcm(plaintext, key) {
  const iv = crypto.randomBytes(AES_IV_LENGTH);
  const cipher = crypto.createCipheriv(AES_ALGORITHM, key, iv, {
    authTagLength: AES_AUTH_TAG_LENGTH,
  });

  let ciphertext = cipher.update(plaintext, "utf8", "hex");
  ciphertext += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");

  return {
    iv: iv.toString("hex"),
    ciphertext,
    authTag,
  };
}

/**
 * Decrypt AES-256-GCM ciphertext.
 *
 * @param {{ iv: string, ciphertext: string, authTag: string }} encryptedData
 * @param {Buffer} key – 256-bit decryption key
 * @returns {string} decrypted plaintext
 * @throws {Error} if authentication tag verification fails
 */
function decryptAesGcm(encryptedData, key) {
  const { iv, ciphertext, authTag } = encryptedData;
  const decipher = crypto.createDecipheriv(
    AES_ALGORITHM,
    key,
    Buffer.from(iv, "hex"),
    { authTagLength: AES_AUTH_TAG_LENGTH }
  );
  decipher.setAuthTag(Buffer.from(authTag, "hex"));

  let plaintext = decipher.update(ciphertext, "hex", "utf8");
  plaintext += decipher.final("utf8");

  return plaintext;
}

/**
 * Generate a random 256-bit AES key.
 * @returns {Buffer}
 */
function generateAesKey() {
  return crypto.randomBytes(AES_KEY_LENGTH);
}

// ---------------------------------------------------------------------------
// ECDH Key Exchange (P-256)
// ---------------------------------------------------------------------------

/**
 * Generate an ephemeral ECDH key pair on the P-256 curve.
 * @returns {{ publicKey: string, ecdh: crypto.ECDH }}
 *   publicKey is hex-encoded for transmission to the peer.
 */
function generateEcdhKeyPair() {
  const ecdh = crypto.createECDH(ECDH_CURVE);
  ecdh.generateKeys();
  return {
    publicKey: ecdh.getPublicKey("hex"),
    ecdh,
  };
}

/**
 * Derive a shared secret from an ECDH key pair and the peer's public key.
 *
 * The resulting shared secret can be used (after a KDF step) as an
 * AES-256 key for encrypted communication.
 *
 * @param {crypto.ECDH} ecdh        – local ECDH instance (with private key)
 * @param {string}      peerPubHex  – peer's public key (hex-encoded)
 * @returns {Buffer} raw shared secret
 */
function deriveSharedSecret(ecdh, peerPubHex) {
  return ecdh.computeSecret(Buffer.from(peerPubHex, "hex"));
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  encryptAesGcm,
  decryptAesGcm,
  generateAesKey,
  generateEcdhKeyPair,
  deriveSharedSecret,
};
