/**
 * okta.js – Okta SSO Authentication & JWKS Verification
 *
 * Cryptographic Algorithms Used:
 *   • RS256 / ES256 via Okta JWKS endpoint – JWT signature verification
 *
 * PQC Impact:
 *   RS256 (RSA)   → CRITICAL (Shor's algorithm breaks RSA key on IdP side)
 *   ES256 (ECDSA) → CRITICAL (Shor's algorithm breaks ECC key on IdP side)
 *
 * Note: Even though the verification happens on the client side, the
 * security guarantee depends on the IdP's public key remaining
 * computationally infeasible to forge. A CRQC would compromise that
 * guarantee, enabling forged tokens that pass verification.
 */

const OktaJwtVerifier = require("@okta/jwt-verifier");

// ---------------------------------------------------------------------------
// Okta Configuration (placeholder values – replace with real tenant info)
// ---------------------------------------------------------------------------

const OKTA_ISSUER = process.env.OKTA_ISSUER || "https://dev-example.okta.com/oauth2/default";
const OKTA_CLIENT_ID = process.env.OKTA_CLIENT_ID || "0oa1bcdef2ghijklmn3o";

// ---------------------------------------------------------------------------
// Okta JWT Verifier Instance
// ---------------------------------------------------------------------------

/**
 * OktaJwtVerifier fetches the JWKS (JSON Web Key Set) from the Okta
 * authorization server and uses the RS256 or ES256 public keys published
 * there to verify incoming access tokens.
 *
 * Quantum Risk:
 *   The public keys exposed at the JWKS endpoint are RSA or ECDSA keys.
 *   A sufficiently powerful quantum computer running Shor's algorithm
 *   could derive the corresponding private key and mint arbitrary tokens
 *   that would pass this verification step.
 */
const oktaVerifier = new OktaJwtVerifier({
  issuer: OKTA_ISSUER,
  clientId: OKTA_CLIENT_ID,
});

// ---------------------------------------------------------------------------
// Token Verification
// ---------------------------------------------------------------------------

/**
 * Verify an Okta-issued access token.
 *
 * Internally delegates to OktaJwtVerifier which:
 *   1. Fetches the JWKS from ${issuer}/v1/keys
 *   2. Finds the signing key by `kid`
 *   3. Verifies the JWT signature using RS256 or ES256
 *   4. Validates standard claims (iss, aud, exp, iat)
 *
 * @param {string} accessToken – Bearer token from the Authorization header
 * @returns {Promise<import("@okta/jwt-verifier").Jwt>} verified JWT object
 * @throws {Error} if the token is invalid, expired, or signature fails
 */
async function verifyOktaAccessToken(accessToken) {
  const jwt = await oktaVerifier.verifyAccessToken(accessToken, "api://default");
  return jwt;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  verifyOktaAccessToken,
};
