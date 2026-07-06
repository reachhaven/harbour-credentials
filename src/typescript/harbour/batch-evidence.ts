/**
 * Batched credential evidence — the single authorization JWT plus per-credential
 * Merkle inclusion proof. Mirror of `harbour/batch_evidence.py`
 * (`docs/specs/batched-credential-evidence.md` §4–6).
 *
 * The authorization JWT is a plain ES256/EdDSA JWS (`typ:
 * harbour-batch-auth+jwt`) whose `nonce` is the base64url Merkle root over the
 * batch; its signing key is a verification method of the authorizer's did:ethr.
 */

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

export const AUTHORIZATION_JWT_TYP = "harbour-batch-auth+jwt";
export const EVIDENCE_TYPE = "harbour:BatchCredentialEvidence";

export interface BatchEvidence {
  type: string[];
  authorizer: string;
  authorization: string;
  merkleProof: {
    type: string;
    path: (MerkleProofStep & { type: string })[];
  };
}

export interface AuthorizationOptions {
  authorizerDid: string;
  audience: string;
  iat?: number;
  kid?: string;
  alg?: string;
}

function resolveAlg(key: CryptoKey): string {
  if (key.algorithm.name === "ECDSA") return "ES256";
  if (key.algorithm.name === "Ed25519") return "EdDSA";
  throw new Error(`Unsupported algorithm: ${key.algorithm.name}`);
}

/** Sign the single batch authorization JWT (§4.3). */
export async function signAuthorization(
  root: string,
  authorizerKey: CryptoKey,
  options: AuthorizationOptions,
): Promise<string> {
  const alg = options.alg ?? resolveAlg(authorizerKey);
  const header = {
    alg,
    typ: AUTHORIZATION_JWT_TYP,
    kid: options.kid ?? `${options.authorizerDid}#controller`,
  };
  const payload = {
    iss: options.authorizerDid,
    aud: options.audience,
    iat: options.iat ?? Math.floor(Date.now() / 1000),
    nonce: root,
  };
  const signer = new CompactSign(
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  signer.setProtectedHeader(header as jose.CompactJWSHeaderParameters);
  return signer.sign(authorizerKey);
}

/** Verify the authorization JWT signature and claims; return its payload. */
export async function verifyAuthorization(
  token: string,
  authorizerPublicKey: CryptoKey,
  options: { expectedAudience?: string; expectedAuthorizer?: string } = {},
): Promise<Record<string, unknown>> {
  let result;
  try {
    result = await compactVerify(token, authorizerPublicKey);
  } catch (e) {
    throw new VerificationError(
      `Authorization JWT verification failed: ${e instanceof Error ? e.message : e}`,
    );
  }
  if (result.protectedHeader.typ !== AUTHORIZATION_JWT_TYP) {
    throw new VerificationError(
      `Unexpected authorization typ: expected '${AUTHORIZATION_JWT_TYP}', got '${result.protectedHeader.typ}'`,
    );
  }
  const payload = JSON.parse(new TextDecoder().decode(result.payload));
  if (options.expectedAuthorizer && payload.iss !== options.expectedAuthorizer) {
    throw new VerificationError(
      `Authorizer mismatch: expected '${options.expectedAuthorizer}', got '${payload.iss}'`,
    );
  }
  if (options.expectedAudience && payload.aud !== options.expectedAudience) {
    throw new VerificationError(
      `Audience mismatch: expected '${options.expectedAudience}', got '${payload.aud}'`,
    );
  }
  if (typeof payload.nonce !== "string") {
    throw new VerificationError("Authorization JWT missing string nonce (Merkle root)");
  }
  return payload;
}

/** Build the BatchCredentialEvidence object for each credential in a batch. */
export async function buildBatchEvidence(
  payloads: Record<string, unknown>[],
  authorizerKey: CryptoKey,
  options: AuthorizationOptions,
): Promise<BatchEvidence[]> {
  if (payloads.length === 0) {
    throw new Error("cannot build batch evidence over an empty batch");
  }
  const leaves = payloads.map(computeLeaf);
  const root = merkleRootB64url(leaves);
  const authorization = await signAuthorization(root, authorizerKey, options);
  return payloads.map((_, i) => ({
    type: [EVIDENCE_TYPE],
    authorizer: options.authorizerDid,
    authorization,
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
  authorizerPublicKey: CryptoKey,
  options: { expectedAudience?: string } = {},
): Promise<Record<string, unknown>> {
  const auth = evidence.authorization;
  if (typeof auth !== "string") {
    throw new VerificationError("BatchCredentialEvidence missing authorization JWT");
  }
  const authorizer = evidence.authorizer;
  const authPayload = await verifyAuthorization(auth, authorizerPublicKey, {
    expectedAudience: options.expectedAudience,
    expectedAuthorizer: typeof authorizer === "string" ? authorizer : undefined,
  });

  const proof = evidence.merkleProof as { path?: MerkleProofStep[] } | undefined;
  if (!proof || !Array.isArray(proof.path)) {
    throw new VerificationError("BatchCredentialEvidence missing merkleProof.path");
  }
  const leaf = computeLeaf(payload);
  const root = b64urlDecode(authPayload.nonce as string);
  if (!verifyInclusion(leaf, proof.path, root)) {
    throw new VerificationError(
      "Merkle inclusion proof does not fold to the signed root",
    );
  }
  return authPayload;
}
