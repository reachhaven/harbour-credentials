/**
 * Sign Verifiable Credentials and Presentations as VC-JOSE-COSE compact JWS.
 */

import * as jose from "jose";
import { CompactSign } from "jose";

export interface SignOptions {
  /** Algorithm override. Default: ES256 for P-256, EdDSA for Ed25519. */
  alg?: string;
  /** Key ID (DID verification method) for the JOSE header. */
  kid?: string;
  /** X.509 certificate chain (base64 DER) for the JOSE header. */
  x5c?: string[];
}

export interface VpSignOptions extends SignOptions {
  /** Challenge nonce for replay protection. */
  nonce?: string;
  /** Intended audience (verifier DID or URL). */
  audience?: string;
}

/**
 * Sign a VC as VC-JOSE-COSE compact JWS.
 *
 * @param vc - The Verifiable Credential JSON-LD object.
 * @param privateKey - CryptoKey (P-256 or Ed25519).
 * @param options - Signing options.
 * @returns Compact JWS string (header.payload.signature).
 */
export async function signVcJose(
  vc: Record<string, unknown>,
  privateKey: CryptoKey,
  options: SignOptions = {},
): Promise<string> {
  const alg = options.alg ?? resolveAlg(privateKey);
  const payload = new TextEncoder().encode(JSON.stringify(vc));

  const signer = new CompactSign(payload);
  const header: Record<string, unknown> = { alg, typ: "vc+ld+jwt" };
  if (options.kid) header.kid = options.kid;
  if (options.x5c) header.x5c = options.x5c;
  signer.setProtectedHeader(header as jose.CompactJWSHeaderParameters);

  return signer.sign(privateKey);
}

/**
 * Sign a VP as VC-JOSE-COSE compact JWS.
 *
 * @param vp - The Verifiable Presentation JSON-LD object.
 * @param privateKey - CryptoKey (P-256 or Ed25519).
 * @param options - Signing options.
 * @returns Compact JWS string (header.payload.signature).
 */
export async function signVpJose(
  vp: Record<string, unknown>,
  privateKey: CryptoKey,
  options: VpSignOptions = {},
): Promise<string> {
  const alg = options.alg ?? resolveAlg(privateKey);

  // Add nonce and audience to the VP payload
  const vpPayload: Record<string, unknown> = { ...vp };
  if (options.nonce !== undefined) vpPayload.nonce = options.nonce;
  if (options.audience !== undefined) vpPayload.aud = options.audience;

  const payload = new TextEncoder().encode(JSON.stringify(vpPayload));

  const signer = new CompactSign(payload);
  const header: Record<string, unknown> = { alg, typ: "vp+ld+jwt" };
  if (options.kid) header.kid = options.kid;
  signer.setProtectedHeader(header as jose.CompactJWSHeaderParameters);

  return signer.sign(privateKey);
}

function resolveAlg(privateKey: CryptoKey): string {
  const alg = privateKey.algorithm;
  if (alg.name === "ECDSA") return "ES256";
  if (alg.name === "Ed25519") return "EdDSA";
  throw new Error(`Unsupported key algorithm: ${alg.name}`);
}
