/**
 * Verify VC-JOSE-COSE compact JWS proofs on Verifiable Credentials/Presentations.
 */

import { compactVerify } from "jose";

export class VerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerificationError";
  }
}

export interface VpVerifyOptions {
  /** If provided, verify the nonce claim matches. */
  expectedNonce?: string;
  /** If provided, verify the aud claim matches. */
  expectedAudience?: string;
}

/**
 * Verify a VC-JOSE-COSE compact JWS and return the VC payload object.
 */
export async function verifyVcJose(
  token: string,
  publicKey: CryptoKey,
): Promise<Record<string, unknown>> {
  return verifyJose(token, publicKey, "vc+jwt");
}

/**
 * Verify a VP-JOSE-COSE compact JWS and return the VP payload object.
 */
export async function verifyVpJose(
  token: string,
  publicKey: CryptoKey,
  options: VpVerifyOptions = {},
): Promise<Record<string, unknown>> {
  const payload = await verifyJose(token, publicKey, "vp+jwt");

  if (options.expectedNonce !== undefined) {
    if (payload.nonce !== options.expectedNonce) {
      throw new VerificationError(
        `Nonce mismatch: expected '${options.expectedNonce}', got '${payload.nonce}'`,
      );
    }
  }

  if (options.expectedAudience !== undefined) {
    if (payload.aud !== options.expectedAudience) {
      throw new VerificationError(
        `Audience mismatch: expected '${options.expectedAudience}', got '${payload.aud}'`,
      );
    }
  }

  return payload;
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

async function verifyJose(
  token: string,
  publicKey: CryptoKey,
  expectedTyp: string,
): Promise<Record<string, unknown>> {
  let result;
  try {
    result = await compactVerify(token, publicKey);
  } catch (e) {
    throw new VerificationError(
      `JWS verification failed: ${e instanceof Error ? e.message : e}`,
    );
  }

  const header = result.protectedHeader;
  if (header.typ !== expectedTyp) {
    throw new VerificationError(
      `Unexpected typ: expected '${expectedTyp}', got '${header.typ}'`,
    );
  }

  try {
    const text = new TextDecoder().decode(result.payload);
    return JSON.parse(text);
  } catch (e) {
    throw new VerificationError(
      `Invalid payload JSON: ${e instanceof Error ? e.message : e}`,
    );
  }
}
