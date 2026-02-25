/**
 * SD-JWT Verifiable Presentations for privacy-preserving consent.
 *
 * This module enables creating VPs where:
 * - The inner credential is an SD-JWT-VC with selectively disclosed claims
 * - The VP envelope includes evidence (e.g., DelegatedSignatureEvidence)
 * - The VP is signed by the holder's key (KB-JWT style binding)
 *
 * The SD-JWT VP format is:
 *   <vp-jwt>~<issuer-jwt>~<disc1>~<disc2>~...~<kb-jwt>
 */

import { CompactSign, compactVerify } from "jose";
import {
  computeTransactionDataParamHash,
  createDelegationChallenge,
  type TransactionData,
} from "./delegation.js";
import { VerificationError } from "./verifier.js";

const SD_JWT_SEPARATOR = "~";
const DELEGATED_EVIDENCE_TYPES = new Set([
  "DelegatedSignatureEvidence",
  "harbour:DelegatedSignatureEvidence",
]);

export interface IssueSdJwtVpOptions {
  /** Which disclosures to include by claim name. null = all, [] = none. */
  disclosures?: string[] | null;
  /** Evidence objects to include in the VP. */
  evidence?: Record<string, unknown>[];
  /** Challenge nonce for replay protection. */
  nonce?: string;
  /** Intended verifier (DID or URL). */
  audience?: string;
  /** Holder's DID. */
  holderDid?: string;
}

export interface VerifySdJwtVpOptions {
  expectedNonce?: string;
  expectedAudience?: string;
}

export interface SdJwtVpResult {
  credential: Record<string, unknown>;
  holder?: string;
  evidence?: Record<string, unknown>[];
  nonce?: string;
  audience?: string;
}

/**
 * Issue an SD-JWT VP with selective disclosure and evidence.
 *
 * @param sdJwtVc - The SD-JWT-VC string (<issuer-jwt>~<disc1>~...~).
 * @param holderPrivateKey - Holder's private key for VP and KB-JWT signatures.
 * @param options - VP options (disclosures, evidence, nonce, audience, holderDid).
 * @returns SD-JWT VP string: <vp-jwt>~<issuer-jwt>~<selected-disclosures>~<kb-jwt>
 */
export async function issueSdJwtVp(
  sdJwtVc: string,
  holderPrivateKey: CryptoKey,
  options: IssueSdJwtVpOptions = {}
): Promise<string> {
  const alg = resolveAlg(holderPrivateKey);

  // Parse the SD-JWT-VC
  const parts = sdJwtVc.split(SD_JWT_SEPARATOR);
  if (parts.length < 2) {
    throw new Error("Invalid SD-JWT-VC format: missing separator");
  }

  const issuerJwt = parts[0];
  const allDisclosures = parts.slice(1).filter((p) => p.length > 0);

  // Build mapping: claim_name -> disclosure_string
  const disclosureMap = new Map<string, string>();
  for (const discB64 of allDisclosures) {
    const discJson = JSON.parse(
      new TextDecoder().decode(base64urlDecode(discB64))
    );
    if (Array.isArray(discJson) && discJson.length === 3) {
      const [, claimName] = discJson;
      disclosureMap.set(claimName as string, discB64);
    }
  }

  // Select which disclosures to include
  let selectedDisclosures: string[];
  if (options.disclosures === null || options.disclosures === undefined) {
    // Include all disclosures
    selectedDisclosures = [...disclosureMap.values()];
  } else {
    // Include only named disclosures
    selectedDisclosures = [];
    for (const name of options.disclosures) {
      const disc = disclosureMap.get(name);
      if (disc) selectedDisclosures.push(disc);
    }
  }

  const delegationBindings = await normalizeDelegationEvidenceForIssue(
    options.evidence
  );

  let resolvedNonce = options.nonce;
  if (delegationBindings.txNonces.length > 0) {
    if (resolvedNonce === undefined) {
      if (delegationBindings.txNonces.length !== 1) {
        throw new Error(
          "DelegatedSignatureEvidence contains multiple transaction_data nonce values; pass explicit nonce"
        );
      }
      resolvedNonce = delegationBindings.txNonces[0];
    } else if (delegationBindings.txNonces.some((n) => n !== resolvedNonce)) {
      throw new Error(
        "Nonce must match DelegatedSignatureEvidence transaction_data.nonce"
      );
    }
  }

  let resolvedAudience = options.audience;
  if (delegationBindings.delegatedTo.length > 0) {
    if (resolvedAudience === undefined) {
      if (delegationBindings.delegatedTo.length !== 1) {
        throw new Error(
          "DelegatedSignatureEvidence contains multiple delegatedTo values; pass explicit audience"
        );
      }
      resolvedAudience = delegationBindings.delegatedTo[0];
    } else if (delegationBindings.delegatedTo.some((a) => a !== resolvedAudience)) {
      throw new Error("Audience must match DelegatedSignatureEvidence delegatedTo");
    }
  }

  // Build VP payload
  const vpPayload: Record<string, unknown> = {
    vp: {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiablePresentation"],
      ...(options.holderDid ? { holder: options.holderDid } : {}),
      ...(delegationBindings.evidence && delegationBindings.evidence.length > 0
        ? { evidence: delegationBindings.evidence }
        : {}),
    },
    iat: Math.floor(Date.now() / 1000),
  };

  if (options.holderDid) {
    vpPayload.iss = options.holderDid;
  }
  if (resolvedNonce) {
    vpPayload.nonce = resolvedNonce;
  }
  if (resolvedAudience) {
    vpPayload.aud = resolvedAudience;
  }

  // Hash of the issuer JWT for binding
  const vcHashBuffer = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(issuerJwt)
  );
  vpPayload._vc_hash = base64urlEncode(new Uint8Array(vcHashBuffer));

  // Sign VP JWT
  const vpPayloadBytes = new TextEncoder().encode(JSON.stringify(vpPayload));
  const vpSigner = new CompactSign(vpPayloadBytes);
  vpSigner.setProtectedHeader({ alg, typ: "vp+sd-jwt" });
  const vpJwt = await vpSigner.sign(holderPrivateKey);

  // Create KB-JWT
  const sdMaterial =
    issuerJwt +
    SD_JWT_SEPARATOR +
    selectedDisclosures.join(SD_JWT_SEPARATOR);
  const sdHashBuffer = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(sdMaterial)
  );
  const kbPayload: Record<string, unknown> = {
    iat: Math.floor(Date.now() / 1000),
    sd_hash: base64urlEncode(new Uint8Array(sdHashBuffer)),
  };
  if (resolvedNonce) kbPayload.nonce = resolvedNonce;
  if (resolvedAudience) kbPayload.aud = resolvedAudience;
  if (delegationBindings.txHashes.length > 0) {
    kbPayload.transaction_data_hashes = delegationBindings.txHashes;
    kbPayload.transaction_data_hashes_alg = "sha-256";
  }

  const kbPayloadBytes = new TextEncoder().encode(JSON.stringify(kbPayload));
  const kbSigner = new CompactSign(kbPayloadBytes);
  kbSigner.setProtectedHeader({ alg, typ: "kb+jwt" });
  const kbJwt = await kbSigner.sign(holderPrivateKey);

  // Compose: vp-jwt~issuer-jwt~disc1~disc2~...~kb-jwt
  return [vpJwt, issuerJwt, ...selectedDisclosures, kbJwt].join(
    SD_JWT_SEPARATOR
  );
}

/**
 * Verify an SD-JWT VP and return disclosed claims and evidence.
 *
 * @param sdJwtVp - The SD-JWT VP string.
 * @param issuerPublicKey - Issuer's public key (for VC verification).
 * @param holderPublicKey - Holder's public key (for VP and KB-JWT verification).
 * @param options - Expected nonce and audience.
 * @returns Verified result with credential claims, evidence, holder, etc.
 */
export async function verifySdJwtVp(
  sdJwtVp: string,
  issuerPublicKey: CryptoKey,
  holderPublicKey: CryptoKey,
  options: VerifySdJwtVpOptions = {}
): Promise<SdJwtVpResult> {
  const parts = sdJwtVp.split(SD_JWT_SEPARATOR);
  if (parts.length < 3) {
    throw new VerificationError("Invalid SD-JWT VP format: too few parts");
  }

  const vpJwt = parts[0];
  const issuerJwt = parts[1];
  const kbJwt = parts[parts.length - 1];
  const disclosures = parts.slice(2, -1);

  // 1. Verify VP JWT (holder)
  let vpResult;
  try {
    vpResult = await compactVerify(vpJwt, holderPublicKey);
  } catch (e) {
    throw new VerificationError(
      `VP JWT verification failed: ${e instanceof Error ? e.message : e}`
    );
  }

  if (vpResult.protectedHeader.typ !== "vp+sd-jwt") {
    throw new VerificationError(
      `Unexpected VP typ: expected 'vp+sd-jwt', got '${vpResult.protectedHeader.typ}'`
    );
  }

  const vpPayload = JSON.parse(
    new TextDecoder().decode(vpResult.payload)
  ) as Record<string, unknown>;

  // 2. Verify issuer JWT (issuer)
  let vcResult;
  try {
    vcResult = await compactVerify(issuerJwt, issuerPublicKey);
  } catch (e) {
    throw new VerificationError(
      `VC JWT verification failed: ${e instanceof Error ? e.message : e}`
    );
  }

  if (vcResult.protectedHeader.typ !== "vc+sd-jwt") {
    throw new VerificationError(
      `Unexpected VC typ: expected 'vc+sd-jwt', got '${vcResult.protectedHeader.typ}'`
    );
  }

  const vcPayload = JSON.parse(
    new TextDecoder().decode(vcResult.payload)
  ) as Record<string, unknown>;

  // 3. Verify KB-JWT (holder)
  let kbResult;
  try {
    kbResult = await compactVerify(kbJwt, holderPublicKey);
  } catch (e) {
    throw new VerificationError(
      `KB-JWT verification failed: ${e instanceof Error ? e.message : e}`
    );
  }

  if (kbResult.protectedHeader.typ !== "kb+jwt") {
    throw new VerificationError(
      `Unexpected KB-JWT typ: expected 'kb+jwt', got '${kbResult.protectedHeader.typ}'`
    );
  }

  const kbPayload = JSON.parse(
    new TextDecoder().decode(kbResult.payload)
  ) as Record<string, unknown>;

  // 4. Verify VC hash binding
  const expectedVcHash = base64urlEncode(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(issuerJwt)
      )
    )
  );

  if (vpPayload._vc_hash !== expectedVcHash) {
    throw new VerificationError(
      "VC hash mismatch: VP does not bind to presented VC"
    );
  }

  // 5. Verify SD hash in KB-JWT
  const sdMaterial =
    issuerJwt +
    SD_JWT_SEPARATOR +
    disclosures.join(SD_JWT_SEPARATOR);
  const expectedSdHash = base64urlEncode(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(sdMaterial)
      )
    )
  );

  if (kbPayload.sd_hash !== expectedSdHash) {
    throw new VerificationError("SD hash mismatch in KB-JWT");
  }

  const vpNonce = typeof vpPayload.nonce === "string" ? vpPayload.nonce : undefined;
  const kbNonce = typeof kbPayload.nonce === "string" ? kbPayload.nonce : undefined;
  if (vpNonce !== kbNonce && (vpNonce !== undefined || kbNonce !== undefined)) {
    throw new VerificationError("Nonce mismatch between VP and KB-JWT");
  }

  const vpAudience = typeof vpPayload.aud === "string" ? vpPayload.aud : undefined;
  const kbAudience =
    typeof kbPayload.aud === "string" ? kbPayload.aud : undefined;
  if (
    vpAudience !== kbAudience &&
    (vpAudience !== undefined || kbAudience !== undefined)
  ) {
    throw new VerificationError("Audience mismatch between VP and KB-JWT");
  }

  const vpObj = isRecord(vpPayload.vp) ? vpPayload.vp : {};
  const evidence = Array.isArray(vpObj.evidence)
    ? (vpObj.evidence as unknown[])
    : undefined;
  const delegationBindings = await deriveDelegationBindingsForVerify(evidence);

  if (delegationBindings.txHashes.length > 0) {
    const kbHashes = kbPayload.transaction_data_hashes;
    if (
      !Array.isArray(kbHashes) ||
      !kbHashes.every((value) => typeof value === "string")
    ) {
      throw new VerificationError(
        "Missing transaction_data_hashes in KB-JWT for delegated evidence"
      );
    }
    if (!stringArraysEqual(kbHashes as string[], delegationBindings.txHashes)) {
      throw new VerificationError("transaction_data_hashes mismatch");
    }
    if (kbPayload.transaction_data_hashes_alg !== "sha-256") {
      throw new VerificationError("transaction_data_hashes_alg must be 'sha-256'");
    }
  }

  if (delegationBindings.txNonces.length > 1) {
    throw new VerificationError(
      "DelegatedSignatureEvidence contains multiple transaction_data nonce values"
    );
  }
  if (
    delegationBindings.txNonces.length === 1 &&
    vpNonce !== delegationBindings.txNonces[0]
  ) {
    throw new VerificationError(
      "Nonce mismatch: VP/KB nonce does not match transaction_data nonce"
    );
  }

  if (delegationBindings.delegatedTo.length > 1) {
    throw new VerificationError(
      "DelegatedSignatureEvidence contains multiple delegatedTo values"
    );
  }
  if (
    delegationBindings.delegatedTo.length === 1 &&
    vpAudience !== delegationBindings.delegatedTo[0]
  ) {
    throw new VerificationError(
      "Audience mismatch: VP/KB audience does not match delegatedTo"
    );
  }

  // 6. Verify nonce
  if (options.expectedNonce !== undefined) {
    if (vpNonce !== options.expectedNonce) {
      throw new VerificationError(
        `Nonce mismatch: expected '${options.expectedNonce}', got '${vpNonce}'`
      );
    }
    if (kbNonce !== options.expectedNonce) {
      throw new VerificationError("Nonce mismatch in KB-JWT");
    }
  }

  // 7. Verify audience
  if (options.expectedAudience !== undefined) {
    if (vpAudience !== options.expectedAudience) {
      throw new VerificationError(
        `Audience mismatch: expected '${options.expectedAudience}', got '${vpAudience}'`
      );
    }
    if (kbAudience !== options.expectedAudience) {
      throw new VerificationError("Audience mismatch in KB-JWT");
    }
  }

  // 8. Process disclosures
  const sdDigests = new Set<string>(
    Array.isArray(vcPayload._sd) ? (vcPayload._sd as string[]) : []
  );
  const disclosedClaims: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(vcPayload)) {
    if (k !== "_sd" && k !== "_sd_alg") {
      disclosedClaims[k] = v;
    }
  }

  for (const discB64 of disclosures) {
    const discHash = base64urlEncode(
      new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(discB64)
        )
      )
    );

    if (!sdDigests.has(discHash)) {
      throw new VerificationError(
        `Disclosure hash ${discHash.slice(0, 16)}... not found in _sd digests`
      );
    }
    sdDigests.delete(discHash);

    const discJson = JSON.parse(
      new TextDecoder().decode(base64urlDecode(discB64))
    );
    if (!Array.isArray(discJson) || discJson.length !== 3) {
      throw new VerificationError(
        "Invalid disclosure format: expected [salt, name, value]"
      );
    }
    const [, claimName, claimValue] = discJson;
    disclosedClaims[claimName as string] = claimValue;
  }

  // Build result
  const result: SdJwtVpResult = {
    credential: disclosedClaims,
  };

  if (typeof vpObj.holder === "string") result.holder = vpObj.holder;
  if (Array.isArray(vpObj.evidence))
    result.evidence = vpObj.evidence as Record<string, unknown>[];
  if (vpNonce) result.nonce = vpNonce;
  if (vpAudience) result.audience = vpAudience;

  return result;
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}

function stringArraysEqual(left: string[], right: string[]): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

interface DelegationBindings {
  evidence?: Record<string, unknown>[];
  txHashes: string[];
  txNonces: string[];
  delegatedTo: string[];
}

function getTransactionDataFromEvidence(
  evidenceItem: Record<string, unknown>,
  errorFactory: (message: string) => Error
): Record<string, unknown> {
  const transactionData = evidenceItem.transaction_data;
  if (transactionData === undefined) {
    throw errorFactory("DelegatedSignatureEvidence requires transaction_data");
  }
  if (!isRecord(transactionData)) {
    throw errorFactory("DelegatedSignatureEvidence transaction data must be an object");
  }
  return transactionData;
}

async function normalizeDelegationEvidenceForIssue(
  evidence?: Record<string, unknown>[]
): Promise<DelegationBindings> {
  if (evidence === undefined) {
    return { txHashes: [], txNonces: [], delegatedTo: [] };
  }

  const normalized: Record<string, unknown>[] = evidence.map((item) => ({
    ...item,
  }));
  const txHashes: string[] = [];
  const txNonces: string[] = [];
  const delegatedTo: string[] = [];

  for (const item of normalized) {
    if (!DELEGATED_EVIDENCE_TYPES.has(String(item.type))) {
      continue;
    }
    const transactionData = getTransactionDataFromEvidence(
      item,
      (message) => new Error(message)
    );
    const tx = transactionData as unknown as TransactionData;
    const challenge = await createDelegationChallenge(tx);
    if (
      typeof item.challenge === "string" &&
      item.challenge !== challenge
    ) {
      throw new Error(
        "DelegatedSignatureEvidence challenge does not match transaction_data"
      );
    }
    item.challenge = challenge;

    txHashes.push(await computeTransactionDataParamHash(tx));
    txNonces.push(tx.nonce);

    if (typeof item.delegatedTo === "string") {
      delegatedTo.push(item.delegatedTo);
    }
  }

  return {
    evidence: normalized,
    txHashes: dedupe(txHashes),
    txNonces: dedupe(txNonces),
    delegatedTo: dedupe(delegatedTo),
  };
}

async function deriveDelegationBindingsForVerify(
  evidence?: unknown[]
): Promise<Omit<DelegationBindings, "evidence">> {
  if (!evidence) {
    return { txHashes: [], txNonces: [], delegatedTo: [] };
  }

  const txHashes: string[] = [];
  const txNonces: string[] = [];
  const delegatedTo: string[] = [];

  for (const evidenceItem of evidence) {
    if (!isRecord(evidenceItem)) continue;
    if (!DELEGATED_EVIDENCE_TYPES.has(String(evidenceItem.type))) continue;

    const transactionData = getTransactionDataFromEvidence(
      evidenceItem,
      (message) => new VerificationError(message)
    );
    const tx = transactionData as unknown as TransactionData;

    const expectedChallenge = await createDelegationChallenge(tx);
    if (
      typeof evidenceItem.challenge === "string" &&
      evidenceItem.challenge !== expectedChallenge
    ) {
      throw new VerificationError(
        "Delegation challenge mismatch in evidence transaction_data"
      );
    }

    txHashes.push(await computeTransactionDataParamHash(tx));
    txNonces.push(tx.nonce);

    if (typeof evidenceItem.delegatedTo === "string") {
      delegatedTo.push(evidenceItem.delegatedTo);
    }
  }

  return {
    txHashes: dedupe(txHashes),
    txNonces: dedupe(txNonces),
    delegatedTo: dedupe(delegatedTo),
  };
}
