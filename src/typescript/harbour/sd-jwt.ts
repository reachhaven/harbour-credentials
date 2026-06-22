/**
 * SD-JWT-VC issuance and verification for JavaScript/TypeScript.
 *
 * Implements SD-JWT-VC using native crypto + jose. Supports both flat and
 * structured (nested, dot-path) selective disclosure per RFC 9901 §6, mirroring
 * the Python `harbour.sd_jwt` module.
 *
 * Issuance is split into `buildSdJwtPayload` (fix salts, produce the issuer
 * payload + disclosures) and `signSdJwt` (sign the possibly-augmented payload),
 * so callers can hash a stable payload before signing — e.g. the Merkle leaf for
 * batched credential evidence (`docs/specs/batched-credential-evidence.md` §4.1).
 */

import { createHash, randomBytes } from "node:crypto";
import * as jose from "jose";
import { CompactSign, compactVerify } from "jose";
import { VerificationError } from "./verifier.js";

const SD_JWT_SEPARATOR = "~";

interface IssueOptions {
  alg?: string;
  x5c?: string[];
  cnf?: Record<string, unknown>;
}

function base64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url").replace(/=+$/, "");
}

function base64urlDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

function resolveAlg(key: CryptoKey): string {
  if (key.algorithm.name === "ECDSA") return "ES256";
  if (key.algorithm.name === "Ed25519") return "EdDSA";
  throw new Error(`Unsupported algorithm: ${key.algorithm.name}`);
}

function createDisclosure(name: string, value: unknown): [string, string] {
  const salt = randomBytes(16).toString("base64url");
  const discB64 = Buffer.from(JSON.stringify([salt, name, value]), "utf-8")
    .toString("base64url")
    .replace(/=+$/, "");
  const digest = createHash("sha256").update(discB64).digest();
  return [discB64, base64urlEncode(digest)];
}

/**
 * Apply structured selective disclosure to a (possibly nested) payload.
 * Dot-path entries (e.g. "credentialSubject.email") place `_sd` digests at the
 * right nesting level; simple names are treated as top-level. Mirrors the
 * Python `_apply_structured_disclosures`.
 */
function applyStructuredDisclosures(
  payload: Record<string, unknown>,
  disclosable: string[],
): { payload: Record<string, unknown>; disclosures: string[] } {
  const result = structuredClone(payload);
  const disclosures: string[] = [];

  for (const path of disclosable) {
    const parts = path.split(".");
    const leafKey = parts[parts.length - 1];
    let parent: unknown = result;
    let reached = true;
    for (const part of parts.slice(0, -1)) {
      if (parent && typeof parent === "object" && part in (parent as object)) {
        parent = (parent as Record<string, unknown>)[part];
      } else {
        reached = false;
        break;
      }
    }
    if (
      reached &&
      parent &&
      typeof parent === "object" &&
      leafKey in (parent as object)
    ) {
      const obj = parent as Record<string, unknown>;
      const value = obj[leafKey];
      delete obj[leafKey];
      const [discB64, digest] = createDisclosure(leafKey, value);
      disclosures.push(discB64);
      if (!Array.isArray(obj._sd)) obj._sd = [];
      (obj._sd as string[]).push(digest);
    }
  }
  return { payload: result, disclosures };
}

/** Build the issuer SD-JWT payload (with `_sd` digests) and its disclosures. */
export function buildSdJwtPayload(
  claims: Record<string, unknown>,
  options: { vct: string; disclosable?: string[]; cnf?: Record<string, unknown> },
): { payload: Record<string, unknown>; disclosures: string[] } {
  const { payload, disclosures } = applyStructuredDisclosures(
    { ...claims, vct: options.vct },
    options.disclosable ?? [],
  );
  if (disclosures.length > 0) payload._sd_alg = "sha-256";
  if (options.cnf) payload.cnf = options.cnf;
  return { payload, disclosures };
}

/** Sign a prepared SD-JWT payload and assemble the compact SD-JWT. */
export async function signSdJwt(
  payload: Record<string, unknown>,
  disclosures: string[],
  privateKey: CryptoKey,
  options: { alg?: string; x5c?: string[] } = {},
): Promise<string> {
  const alg = options.alg ?? resolveAlg(privateKey);
  const header: Record<string, unknown> = { alg, typ: "vc+sd-jwt" };
  if (options.x5c) header.x5c = options.x5c;
  const signer = new CompactSign(
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  signer.setProtectedHeader(header as jose.CompactJWSHeaderParameters);
  const issuerJwt = await signer.sign(privateKey);
  return [issuerJwt, ...disclosures, ""].join(SD_JWT_SEPARATOR);
}

/** Issue an SD-JWT-VC credential (thin wrapper over build + sign). */
export async function issueSdJwtVc(
  claims: Record<string, unknown>,
  privateKey: CryptoKey,
  options: { vct: string; disclosable?: string[] } & IssueOptions,
): Promise<string> {
  const { payload, disclosures } = buildSdJwtPayload(claims, {
    vct: options.vct,
    disclosable: options.disclosable,
    cnf: options.cnf,
  });
  return signSdJwt(payload, disclosures, privateKey, {
    alg: options.alg,
    x5c: options.x5c,
  });
}

// --- verification -----------------------------------------------------------

function collectSdDigests(obj: unknown): Set<string> {
  const digests = new Set<string>();
  if (Array.isArray(obj)) {
    for (const item of obj) for (const d of collectSdDigests(item)) digests.add(d);
  } else if (obj && typeof obj === "object") {
    for (const d of ((obj as Record<string, unknown>)._sd as string[]) ?? []) {
      digests.add(d);
    }
    for (const v of Object.values(obj as Record<string, unknown>)) {
      for (const d of collectSdDigests(v)) digests.add(d);
    }
  }
  return digests;
}

function insertDisclosureRecursive(
  obj: Record<string, unknown>,
  name: string,
  value: unknown,
  digest: string,
): boolean {
  const sd = obj._sd as string[] | undefined;
  if (Array.isArray(sd) && sd.includes(digest)) {
    obj[name] = value;
    obj._sd = sd.filter((d) => d !== digest);
    if ((obj._sd as string[]).length === 0) delete obj._sd;
    return true;
  }
  for (const v of Object.values(obj)) {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      if (insertDisclosureRecursive(v as Record<string, unknown>, name, value, digest)) {
        return true;
      }
    }
  }
  return false;
}

function cleanSdMetadata(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(cleanSdMetadata);
  if (obj && typeof obj === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      if (k !== "_sd" && k !== "_sd_alg") out[k] = cleanSdMetadata(v);
    }
    return out;
  }
  return obj;
}

/** Verify an SD-JWT-VC and return all disclosed claims (recursive `_sd`). */
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

  const allDigests = collectSdDigests(payload);
  for (const discB64 of discStrings) {
    const discHash = base64urlEncode(
      createHash("sha256").update(discB64).digest(),
    );
    if (!allDigests.has(discHash)) {
      throw new VerificationError("Disclosure hash not found in _sd digests");
    }
    allDigests.delete(discHash);
    const discJson = JSON.parse(
      new TextDecoder().decode(base64urlDecode(discB64)),
    );
    if (!Array.isArray(discJson) || discJson.length !== 3) {
      throw new VerificationError("Invalid disclosure format");
    }
    const [, claimName, claimValue] = discJson;
    if (!insertDisclosureRecursive(payload, claimName, claimValue, discHash)) {
      throw new VerificationError(
        `Could not locate _sd digest for claim '${claimName}'`,
      );
    }
  }

  return cleanSdMetadata(payload) as Record<string, unknown>;
}
