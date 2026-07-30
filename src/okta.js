/**
 * okta.js – Auth0 (Okta CIC) SSO Authentication & JWKS Verification
 *
 * Cryptographic Algorithms Used:
 *   • RS256 via Auth0 JWKS endpoint – JWT signature verification
 *
 * PQC Impact:
 *   RS256 (RSA)   → CRITICAL (Shor's algorithm breaks RSA key on IdP side)
 *
 * Note: Even though the verification happens on the client side, the
 * security guarantee depends on the IdP's public key remaining
 * computationally infeasible to forge. A CRQC would compromise that
 * guarantee, enabling forged tokens that pass verification.
 */

const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");

// ---------------------------------------------------------------------------
// Auth0 Configuration
// ---------------------------------------------------------------------------

const OKTA_ISSUER = process.env.OKTA_ISSUER || "https://cypherlens.cic-demo-platform.auth0app.com/";
// Auth0 JWKS endpoints are typically located at /.well-known/jwks.json
const JWKS_URI = `${OKTA_ISSUER.replace(/\/$/, '')}/.well-known/jwks.json`;

// ---------------------------------------------------------------------------
// JWKS Client Instance
// ---------------------------------------------------------------------------

/**
 * jwksClient fetches the JWKS (JSON Web Key Set) from Auth0
 *
 * Quantum Risk:
 *   The public keys exposed at the JWKS endpoint are RSA keys.
 *   A sufficiently powerful quantum computer running Shor's algorithm
 *   could derive the corresponding private key and mint arbitrary tokens.
 */
const client = jwksClient({
  jwksUri: JWKS_URI,
  cache: true,
  rateLimit: true,
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, function(err, key) {
    if (err) {
      return callback(err, null);
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

// ---------------------------------------------------------------------------
// Token Verification
// ---------------------------------------------------------------------------

/**
 * Verify an Auth0-issued access token using RS256.
 *
 * @param {string} accessToken – Bearer token from the Authorization header
 * @returns {Promise<object>} verified JWT object
 */
function verifyOktaAccessToken(accessToken) {
  return new Promise((resolve, reject) => {
    // We only expect RS256 as per Auth0 defaults for SPA
    jwt.verify(accessToken, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
      if (err) {
        return reject(err);
      }
      
      // Structure the response to match what the frontend expects from the previous okta verifier
      resolve({ claims: decoded });
    });
  });
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  verifyOktaAccessToken,
};
