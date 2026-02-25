/**
 * Key Binding JWT (KB-JWT) for SD-JWT-VC presentation.
 *
 * Supports OIDC4VP transaction_data binding per spec:
 * the holder creates a KB-JWT that includes transaction_data_hashes.
 */

import { timingSafeEqual as _timingSafeEqual } from "node:crypto";
import * as jose from "jose";

const SD_JWT_SEPARATOR = "~";

export interface KbJwtOptions {
  nonce: string;
  audience: string;
  transaction_data?: string[];
}

export interface KbJwtPayload {
  nonce: string;
  aud: string;
  iat: number;
  sd_hash: string;
  transaction_data_hashes?: string[];
  transaction_data_hashes_alg?: string;
}

/**
 * Create a Key Binding JWT for SD-JWT-VC presentation.
 *
 * Appends the KB-JWT to the SD-JWT string (after the trailing ~).
 *
 * @param sdJwt - The SD-JWT compact string (ending with ~).
 * @param holderPrivateKey - Holder's private key.
 * @param options - KB-JWT options (nonce, audience, transaction_data).
 * @returns Complete SD-JWT-VC + KB-JWT string.
 */
export async function createKbJwt(
  sdJwt: string,
  holderPrivateKey: CryptoKey,
  options: KbJwtOptions
): Promise<string> {
  const { nonce, audience, transaction_data } = options;

  // Compute sd_hash (SHA-256 of the issuer-jwt part)
  const issuerJwt = sdJwt.split(SD_JWT_SEPARATOR)[0];
  const issuerJwtBytes = new TextEncoder().encode(issuerJwt);
  const hashBuffer = await crypto.subtle.digest("SHA-256", issuerJwtBytes);
  const sdHash = base64urlEncode(new Uint8Array(hashBuffer));

  // Build KB-JWT payload
  const kbPayload: KbJwtPayload = {
    nonce,
    aud: audience,
    iat: Math.floor(Date.now() / 1000),
    sd_hash: sdHash,
  };

  if (transaction_data && transaction_data.length > 0) {
    const tdHashes: string[] = [];
    for (const td of transaction_data) {
      const tdBytes = new TextEncoder().encode(td);
      const tdHash = await crypto.subtle.digest("SHA-256", tdBytes);
      tdHashes.push(base64urlEncode(new Uint8Array(tdHash)));
    }
    kbPayload.transaction_data_hashes = tdHashes;
    kbPayload.transaction_data_hashes_alg = "sha-256";
  }

  // Sign KB-JWT
  const alg = resolveAlg(holderPrivateKey);
  const kbJwt = await new jose.SignJWT(kbPayload as unknown as jose.JWTPayload)
    .setProtectedHeader({ alg, typ: "kb+jwt" })
    .sign(holderPrivateKey);

  // Ensure sdJwt ends with ~ then append kb_jwt
  const normalizedSdJwt = sdJwt.endsWith(SD_JWT_SEPARATOR)
    ? sdJwt
    : sdJwt + SD_JWT_SEPARATOR;
  return normalizedSdJwt + kbJwt;
}

export class KbJwtVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KbJwtVerificationError";
  }
}

export interface KbJwtVerifyOptions {
  expectedNonce: string;
  expectedAudience: string;
  expected_transaction_data?: string[];
}

/**
 * Verify KB-JWT and optionally validate transaction_data_hashes.
 *
 * @param sdJwtWithKb - Complete SD-JWT-VC + KB-JWT string.
 * @param holderPublicKey - Holder's public key.
 * @param options - Verification options.
 * @returns The KB-JWT payload.
 * @throws KbJwtVerificationError if verification fails.
 */
export async function verifyKbJwt(
  sdJwtWithKb: string,
  holderPublicKey: CryptoKey,
  options: KbJwtVerifyOptions
): Promise<KbJwtPayload> {
  const { expectedNonce, expectedAudience, expected_transaction_data } = options;

  // Split: the KB-JWT is the last segment
  const parts = sdJwtWithKb.split(SD_JWT_SEPARATOR);
  if (parts.length < 2) {
    throw new KbJwtVerificationError("Invalid SD-JWT+KB format: too few parts");
  }

  const kbJwt = parts[parts.length - 1];
  if (!kbJwt) {
    throw new KbJwtVerificationError("No KB-JWT found (empty trailing segment)");
  }

  // Verify KB-JWT signature
  let payload: KbJwtPayload;
  try {
    const result = await jose.jwtVerify(kbJwt, holderPublicKey, {
      algorithms: ["ES256", "EdDSA"],
    });
    payload = result.payload as unknown as KbJwtPayload;
  } catch (e) {
    throw new KbJwtVerificationError(
      `KB-JWT verification failed: ${e instanceof Error ? e.message : e}`
    );
  }

  // Validate typ header
  const header = jose.decodeProtectedHeader(kbJwt);
  if (header.typ !== "kb+jwt") {
    throw new KbJwtVerificationError(
      `Unexpected KB-JWT typ: expected 'kb+jwt', got '${header.typ}'`
    );
  }

  // Verify nonce
  if (payload.nonce !== expectedNonce) {
    throw new KbJwtVerificationError(
      `Nonce mismatch: expected '${expectedNonce}', got '${payload.nonce}'`
    );
  }

  // Verify audience
  if (payload.aud !== expectedAudience) {
    throw new KbJwtVerificationError(
      `Audience mismatch: expected '${expectedAudience}', got '${payload.aud}'`
    );
  }

  // Verify sd_hash
  const issuerJwt = parts[0];
  const issuerJwtBytes = new TextEncoder().encode(issuerJwt);
  const expectedHashBuffer = await crypto.subtle.digest("SHA-256", issuerJwtBytes);
  const expectedSdHash = base64urlEncode(new Uint8Array(expectedHashBuffer));

  if (payload.sd_hash !== expectedSdHash) {
    throw new KbJwtVerificationError("sd_hash mismatch");
  }

  // Verify transaction_data_hashes if expected
  if (expected_transaction_data && expected_transaction_data.length > 0) {
    const expectedHashes: string[] = [];
    for (const td of expected_transaction_data) {
      const tdBytes = new TextEncoder().encode(td);
      const tdHash = await crypto.subtle.digest("SHA-256", tdBytes);
      expectedHashes.push(base64urlEncode(new Uint8Array(tdHash)));
    }

    const actualHashes = payload.transaction_data_hashes || [];
    // Use constant-length comparison to avoid timing side-channels
    const match =
      actualHashes.length === expectedHashes.length &&
      actualHashes.reduce(
        (acc: boolean, h, i) => acc && timingSafeEqual(h, expectedHashes[i]),
        true,
      );
    if (!match) {
      throw new KbJwtVerificationError("transaction_data_hashes mismatch");
    }

    if (payload.transaction_data_hashes_alg !== "sha-256") {
      throw new KbJwtVerificationError(
        "transaction_data_hashes_alg must be 'sha-256'"
      );
    }
  }

  return payload;
}

// Helper: resolve algorithm from key type
function resolveAlg(key: CryptoKey): string {
  if (key.algorithm.name === "ECDSA") return "ES256";
  if (key.algorithm.name === "Ed25519") return "EdDSA";
  throw new Error(`Unsupported key algorithm: ${key.algorithm.name}`);
}

// Helper: Base64url encode without padding
function base64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64url")
    .replace(/=+$/, "");
}

// Helper: constant-time string comparison to avoid timing side-channels
function timingSafeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return _timingSafeEqual(bufA, bufB);
}
