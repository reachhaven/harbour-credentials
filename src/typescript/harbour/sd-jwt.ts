/**
 * SD-JWT-VC issuance and verification for JavaScript/TypeScript.
 *
 * Implements SD-JWT-VC using native crypto + jose, without external SD-JWT libs
 * for maximum portability.
 */

import * as jose from "jose";
import { CompactSign, compactVerify } from "jose";
import { VerificationError } from "./verifier.js";

const SD_JWT_SEPARATOR = "~";

interface IssueOptions {
  /** Algorithm override (default: ES256 for P-256). */
  alg?: string;
  /** X.509 certificate chain. */
  x5c?: string[];
  /** Holder confirmation key (for key binding). */
  cnf?: Record<string, unknown>;
}

/**
 * Issue an SD-JWT-VC credential.
 */
export async function issueSdJwtVc(
  claims: Record<string, unknown>,
  privateKey: CryptoKey,
  options: {
    vct: string;
    disclosable?: string[];
  } & IssueOptions,
): Promise<string> {
  const alg = options.alg ?? resolveAlg(privateKey);
  const disclosable = new Set(options.disclosable ?? []);

  const disclosedClaims: Record<string, unknown> = { vct: options.vct };
  const disclosures: string[] = [];
  const sdDigests: string[] = [];

  for (const [key, value] of Object.entries(claims)) {
    if (disclosable.has(key)) {
      const salt = crypto.randomUUID().replace(/-/g, "");
      const discArray = [salt, key, value];
      const discJson = new TextEncoder().encode(JSON.stringify(discArray));
      const discB64 = base64urlEncode(discJson);
      disclosures.push(discB64);

      const hash = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(discB64),
      );
      sdDigests.push(base64urlEncode(new Uint8Array(hash)));
    } else {
      disclosedClaims[key] = value;
    }
  }

  const payload: Record<string, unknown> = { ...disclosedClaims };
  if (sdDigests.length > 0) {
    payload._sd = sdDigests;
    payload._sd_alg = "sha-256";
  }
  if (options.cnf) {
    payload.cnf = options.cnf;
  }

  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  const signer = new CompactSign(payloadBytes);
  const header: Record<string, unknown> = { alg, typ: "vc+sd-jwt" };
  if (options.x5c) header.x5c = options.x5c;
  signer.setProtectedHeader(header as jose.CompactJWSHeaderParameters);

  const issuerJwt = await signer.sign(privateKey);
  return [issuerJwt, ...disclosures, ""].join(SD_JWT_SEPARATOR);
}

/**
 * Verify an SD-JWT-VC and return all disclosed claims.
 */
export async function verifySdJwtVc(
  sdJwt: string,
  publicKey: CryptoKey,
  options: { expectedVct?: string } = {},
): Promise<Record<string, unknown>> {
  const parts = sdJwt.split(SD_JWT_SEPARATOR);
  if (parts.length < 2) {
    throw new VerificationError("Invalid SD-JWT format");
  }

  const issuerJwt = parts[0];
  const discStrings = parts.slice(1).filter((p) => p.length > 0);

  let result;
  try {
    result = await compactVerify(issuerJwt, publicKey);
  } catch (e) {
    throw new VerificationError(
      `SD-JWT verification failed: ${e instanceof Error ? e.message : e}`,
    );
  }

  if (result.protectedHeader.typ !== "vc+sd-jwt") {
    throw new VerificationError(
      `Unexpected typ: expected 'vc+sd-jwt', got '${result.protectedHeader.typ}'`,
    );
  }

  const payload = JSON.parse(new TextDecoder().decode(result.payload));

  if (options.expectedVct && payload.vct !== options.expectedVct) {
    throw new VerificationError(
      `VCT mismatch: expected '${options.expectedVct}', got '${payload.vct}'`,
    );
  }

  const sdDigests = new Set<string>(payload._sd ?? []);
  const disclosed: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(payload)) {
    if (k !== "_sd" && k !== "_sd_alg") {
      disclosed[k] = v;
    }
  }

  for (const discB64 of discStrings) {
    const hash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(discB64),
    );
    const discHash = base64urlEncode(new Uint8Array(hash));
    if (!sdDigests.has(discHash)) {
      throw new VerificationError("Disclosure hash not found in _sd digests");
    }
    sdDigests.delete(discHash);

    const discJson = JSON.parse(
      new TextDecoder().decode(base64urlDecode(discB64)),
    );
    if (!Array.isArray(discJson) || discJson.length !== 3) {
      throw new VerificationError("Invalid disclosure format");
    }
    const [, claimName, claimValue] = discJson;
    disclosed[claimName] = claimValue;
  }

  return disclosed;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function resolveAlg(key: CryptoKey): string {
  if (key.algorithm.name === "ECDSA") return "ES256";
  if (key.algorithm.name === "Ed25519") return "EdDSA";
  throw new Error(`Unsupported algorithm: ${key.algorithm.name}`);
}

function base64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64url")
    .replace(/=+$/, "");
}

function base64urlDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}
