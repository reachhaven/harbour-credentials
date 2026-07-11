/**
 * Batched credential evidence — one wallet KB-JWT plus per-credential Merkle
 * inclusion proof. Mirror of `harbour/batch_evidence.py`
 * (`docs/specs/batched-credential-evidence.md` §4–6).
 *
 * Wallets cannot produce arbitrary JWS signatures: the KB-JWT of an OID4VP
 * presentation is the only signature obtainable from a wallet, so the KB-JWT
 * `nonce` carries SHA-256(message) (lowercase hex) and the SIWE-style message
 * carries the batch Merkle root in its statement line (§4.3). The signing
 * wallet key is a verification method of the authorizer's did:ethr; a
 * verifier resolves that DID (as of the KB-JWT `iat`) to obtain it. The
 * KB-JWT carries no `iss` and no `kid`.
 */

import { createHash, randomBytes } from "node:crypto";
import * as jose from "jose";
import { CompactSign, compactVerify } from "jose";
import { VerificationError } from "./verifier.js";
import {
  b64urlDecode,
  computeLeaf,
  inclusionProof,
  merkleRootB64url,
  verifyInclusion,
  type MerkleProofStep,
} from "./merkle.js";

/** typ header of the batch authorization token — an OID4VP KB-JWT (§4.3). */
export const AUTHORIZATION_JWT_TYP = "kb+jwt";
export const EVIDENCE_TYPE = "harbour:BatchCredentialEvidence";

/**
 * Normative statement grammar (§4.3.1): exactly one such line per message;
 * the root is base64url unpadded SHA-256 (43 chars).
 */
export const STATEMENT_TEMPLATE = (n: number, root: string): string =>
  `I authorize the issuance of ${n} credential(s) committed to by Merkle root ${root}.`;
const STATEMENT_RE =
  /^I authorize the issuance of (\d+) credential\(s\) committed to by Merkle root ([A-Za-z0-9_-]{43})\.$/gm;

export interface BatchEvidence {
  type: string[];
  authorizedBy: string;
  authorization: string;
  authorizationMessage: string;
  merkleProof: {
    type: string;
    path: (MerkleProofStep & { type: string })[];
  };
}

export interface AuthorizationOptions {
  /**
   * The authorizer organization's did:ethr (evidence `authorizedBy`).
   * For the identity credentials it MUST equal each payload's `issuer`
   * (spec §6, step 6 — verifiers enforce the equality).
   */
  authorizedBy: string;
  /** The OID4VP intake verifier's client identifier (the JWT `aud`). */
  audience: string;
  /**
   * The sd_hash binding the KB-JWT to the presented credential — REQUIRED
   * in every KB-JWT (RFC 9901 §4.3); downstream verifiers ignore its value.
   */
  sdHash: string;
  /** Message ceremony metadata (§4.3.1). */
  domain?: string;
  ceremonyNonce?: string;
  issuedAt?: string;
  iat?: number;
  alg?: string;
}

function resolveAlg(key: CryptoKey): string {
  if (key.algorithm.name === "ECDSA") return "ES256";
  if (key.algorithm.name === "Ed25519") return "EdDSA";
  throw new Error(`Unsupported algorithm: ${key.algorithm.name}`);
}

/** SHA-256 of the message as received, lowercase hex (§4.3.1). */
function messageHash(message: string): string {
  return createHash("sha256").update(message, "utf-8").digest("hex");
}

/**
 * Compose a SIWE-style authorization message around the batch root.
 *
 * Only the statement line is normative (§4.3.1); the surrounding SIWE-style
 * fields are ceremony metadata, carried verbatim in the evidence and hashed
 * as-is. In production the message is composed by the intake service
 * (gatehouse) and shown on the wallet's consent screen; this helper produces
 * an equivalent message for pipelines and tests.
 */
export function composeAuthorizationMessage(
  root: string,
  batchSize: number,
  options: { domain: string; address: string; nonce?: string; issuedAt?: string },
): string {
  const statement = STATEMENT_TEMPLATE(batchSize, root);
  const nonce = options.nonce ?? randomBytes(8).toString("hex");
  const issuedAt = options.issuedAt ?? new Date().toISOString().replace(/\.\d{3}Z$/, "+00:00");
  return (
    `${options.domain} wants you to sign this authorization with your wallet:\n` +
    `${options.address}\n` +
    `\n` +
    `${statement}\n` +
    `\n` +
    `Version: 1\n` +
    `Nonce: ${nonce}\n` +
    `Issued At: ${issuedAt}`
  );
}

/**
 * Extract `[root, batchSize]` from the message's statement line.
 *
 * Throws unless the message contains exactly one statement line matching the
 * normative template (§4.3.1).
 */
export function extractRootFromMessage(message: string): [string, number] {
  const matches = [...message.matchAll(STATEMENT_RE)];
  if (matches.length !== 1) {
    throw new VerificationError(
      `authorizationMessage must contain exactly one statement line matching the batch-root template (found ${matches.length})`,
    );
  }
  return [matches[0][2], Number(matches[0][1])];
}

/**
 * Sign the batch authorization KB-JWT over `message` (§4.3).
 *
 * Simulates the wallet's side of the OID4VP ceremony: a KB-JWT
 * (`typ: kb+jwt`, no `iss`, no `kid`) whose `nonce` is the SHA-256 hex of
 * the message shown on the consent screen. In production this token is
 * produced by the admin's wallet through the intake service (gatehouse).
 */
export async function signAuthorization(
  message: string,
  walletKey: CryptoKey,
  options: { audience: string; sdHash: string; iat?: number; alg?: string },
): Promise<string> {
  const alg = options.alg ?? resolveAlg(walletKey);
  const header = { alg, typ: AUTHORIZATION_JWT_TYP };
  const payload: Record<string, unknown> = {
    // Floor a caller-supplied iat too — the Python mirror coerces int(iat),
    // and a fractional iat would mint a token the other runtime rejects.
    iat: Math.floor(options.iat ?? Date.now() / 1000),
    aud: options.audience,
    nonce: messageHash(message),
    sd_hash: options.sdHash,
  };
  const signer = new CompactSign(
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  signer.setProtectedHeader(header as jose.CompactJWSHeaderParameters);
  return signer.sign(walletKey);
}

/**
 * Verify the authorization KB-JWT signature and message commitment.
 *
 * `walletPublicKey` is an admin wallet public key — a verification method of
 * the `authorizedBy` DID document, resolved by the caller as of the KB-JWT
 * `iat` (§6, step 5); a KB-JWT has no `iss` to compare.
 */
export async function verifyAuthorization(
  token: string,
  walletPublicKey: CryptoKey,
  options: { message: string; expectedAudience?: string },
): Promise<Record<string, unknown>> {
  let result;
  try {
    result = await compactVerify(token, walletPublicKey);
  } catch (e) {
    throw new VerificationError(
      `Authorization KB-JWT verification failed: ${e instanceof Error ? e.message : e}`,
    );
  }
  if (result.protectedHeader.typ !== AUTHORIZATION_JWT_TYP) {
    throw new VerificationError(
      `Unexpected authorization typ: expected '${AUTHORIZATION_JWT_TYP}', got '${result.protectedHeader.typ}'`,
    );
  }
  const payload = JSON.parse(new TextDecoder().decode(result.payload));
  if (!Number.isInteger(payload.iat)) {
    throw new VerificationError("Authorization KB-JWT missing integer iat");
  }
  // `!== undefined`, not falsy: an explicit empty-string audience must still
  // be enforced (Python mirror checks `is not None`).
  if (
    options.expectedAudience !== undefined &&
    payload.aud !== options.expectedAudience
  ) {
    throw new VerificationError(
      `Audience mismatch: expected '${options.expectedAudience}', got '${payload.aud}'`,
    );
  }
  if (payload.nonce !== messageHash(options.message)) {
    throw new VerificationError(
      "KB-JWT nonce does not match SHA-256(authorizationMessage)",
    );
  }
  return payload;
}

/** Build the BatchCredentialEvidence object for each credential in a batch. */
export async function buildBatchEvidence(
  payloads: Record<string, unknown>[],
  walletKey: CryptoKey,
  options: AuthorizationOptions,
): Promise<BatchEvidence[]> {
  if (payloads.length === 0) {
    throw new Error("cannot build batch evidence over an empty batch");
  }
  const leaves = payloads.map(computeLeaf);
  const root = merkleRootB64url(leaves);
  const message = composeAuthorizationMessage(root, payloads.length, {
    domain: options.domain ?? "harbour.local",
    address: options.authorizedBy,
    nonce: options.ceremonyNonce,
    issuedAt: options.issuedAt,
  });
  const authorization = await signAuthorization(message, walletKey, {
    audience: options.audience,
    sdHash: options.sdHash,
    iat: options.iat,
    alg: options.alg,
  });
  return payloads.map((_, i) => ({
    type: [EVIDENCE_TYPE],
    authorizedBy: options.authorizedBy,
    authorization,
    authorizationMessage: message,
    // Each nested object carries its JSON-LD type so the evidence remains a
    // valid harbour:MerkleProof / harbour:MerklePathElement under the closed
    // SHACL shapes (spec §5).
    merkleProof: {
      type: "harbour:MerkleProof",
      path: inclusionProof(leaves, i).map((step) => ({
        type: "harbour:MerklePathElement",
        ...step,
      })),
    },
  }));
}

/** Verify one credential's batch evidence in isolation (§6, steps 2–5). */
export async function verifyBatchEvidence(
  payload: Record<string, unknown>,
  evidence: Record<string, unknown>,
  walletPublicKey: CryptoKey,
  options: { expectedAudience?: string } = {},
): Promise<Record<string, unknown>> {
  const auth = evidence.authorization;
  if (typeof auth !== "string") {
    throw new VerificationError("BatchCredentialEvidence missing authorization KB-JWT");
  }
  const message = evidence.authorizationMessage;
  if (typeof message !== "string") {
    throw new VerificationError("BatchCredentialEvidence missing authorizationMessage");
  }

  const authPayload = await verifyAuthorization(auth, walletPublicKey, {
    message,
    expectedAudience: options.expectedAudience,
  });

  const [rootB64] = extractRootFromMessage(message);

  const proof = evidence.merkleProof as { path?: MerkleProofStep[] } | undefined;
  if (!proof || !Array.isArray(proof.path)) {
    throw new VerificationError("BatchCredentialEvidence missing merkleProof.path");
  }
  const leaf = computeLeaf(payload);
  const root = b64urlDecode(rootB64);
  if (!verifyInclusion(leaf, proof.path, root)) {
    throw new VerificationError(
      "Merkle inclusion proof does not fold to the committed root",
    );
  }
  return authPayload;
}
