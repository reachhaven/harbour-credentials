/**
 * SD-JWT-VC issuance and verification for JavaScript/TypeScript.
 *
 * Implements SD-JWT-VC using native crypto + jose. Supports both flat and
 * structured (nested, dot-path) selective disclosure per RFC 9901 §6, mirroring
 * the Python `harbour.sd_jwt` module.
 *
 * Issuance is split into `buildSdJwtPayload` (fix salts, produce the issuer
 * payload + disclosures) and `signSdJwt` (sign the possibly-augmented payload),
 * so a caller can hash the exact payload a human approves (with its `_sd`
 * digests, so the hash survives selective disclosure) before the issuer key
 * signs it. `issueSdJwtVc` does both in one call.
 */

import { createHash, randomBytes } from "node:crypto";
import * as jose from "jose";
import { CompactSign, compactVerify } from "jose";
import { VerificationError } from "./verifier.js";

const SD_JWT_SEPARATOR = "~";

/**
 * SD-JWT-VC JOSE typ. [SD-JWT-VC] draft-14 renamed vc+sd-jwt -> dc+sd-jwt to
 * avoid the clash with W3C VC-JOSE-COSE's application/vc+sd-jwt; verifiers
 * SHOULD accept the pre-rename value during the transition
 * (docs/specs/references/sd-jwt-vc.md).
 */
export const SD_JWT_VC_TYP = "dc+sd-jwt";
export const ACCEPTED_SD_JWT_VC_TYPS: readonly string[] = [
  SD_JWT_VC_TYP,
  "vc+sd-jwt",
];

/**
 * Registered claims [SD-JWT-VC] forbids making selectively disclosable (a
 * verifier needs them to process the credential at all), plus SD-JWT's own
 * metadata (RFC 9901 §4.1.1).
 */
export const NON_DISCLOSABLE_CLAIMS: ReadonlySet<string> = new Set([
  "iss",
  "nbf",
  "exp",
  "cnf",
  "vct",
  "vct#integrity",
  "status",
  "_sd",
  "_sd_alg",
]);

interface IssueOptions {
  /** Algorithm override (default: ES256 for P-256). */
  alg?: string;
  /** X.509 certificate chain. */
  x5c?: string[];
  /** Holder confirmation key (for key binding). */
  cnf?: Record<string, unknown>;
  /** Verification-method DID URL for the JOSE header. */
  kid?: string;
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

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/**
 * Normalize and validate disclosable paths before anything is concealed.
 *
 * Rejects (rather than silently issuing an unverifiable credential):
 * - paths under a reserved top-level claim — the whole claim, including its
 *   members (e.g. `status.status_list`, `cnf.jwk`), must stay in plaintext
 *   ([SD-JWT-VC] §3.2.2.2);
 * - overlapping paths (one a prefix of, or equal to, another): the child's
 *   digest would be concealed inside the parent's disclosure, which the
 *   verifier does not resolve recursively.
 */
function normalizeDisclosablePaths(disclosable: (string | string[])[]): string[][] {
  const paths = disclosable.map((p) => (typeof p === "string" ? p.split(".") : [...p]));
  for (const parts of paths) {
    if (parts.length === 0) throw new Error("empty disclosable path");
    if (NON_DISCLOSABLE_CLAIMS.has(parts[0])) {
      throw new Error(
        parts.length === 1
          ? `claim '${parts[0]}' must not be selectively disclosable ([SD-JWT-VC] registered claims)`
          : `claim '${parts[0]}' must not be selectively disclosable, nor any of its members: ${JSON.stringify(parts)} ([SD-JWT-VC] registered claims)`,
      );
    }
  }
  for (let i = 0; i < paths.length; i++) {
    for (let j = i + 1; j < paths.length; j++) {
      const [a, b] = paths[i].length <= paths[j].length ? [paths[i], paths[j]] : [paths[j], paths[i]];
      if (a.every((seg, k) => seg === b[k])) {
        throw new Error(
          `overlapping disclosable paths: ${JSON.stringify(a)} and ${JSON.stringify(b)}`,
        );
      }
    }
  }
  return paths;
}

/**
 * Apply structured selective disclosure to a (possibly nested) payload.
 * Each entry is either an array of exact key segments (safe for keys that
 * themselves contain dots, e.g. ["credentialSubject", "harbour.gx:labelLevel"])
 * or a dot-separated string ("credentialSubject.email"; a simple name is a
 * top-level claim). `_sd` digests are placed at the right nesting level per
 * RFC 9901 §6.2. Mirrors the Python `_apply_structured_disclosures`.
 *
 * Throws if a declared path does not resolve to an own property of nested
 * objects — a declared-but-missing disclosure is a caller bug, and skipping
 * it would silently issue the claim in plaintext. Array elements (and paths
 * through arrays) are not supported: the verifier does not resolve array
 * digests (RFC 9901 §4.2.4.2), so such credentials would not verify.
 */
function applyStructuredDisclosures(
  payload: Record<string, unknown>,
  disclosable: (string | string[])[],
): { payload: Record<string, unknown>; disclosures: string[] } {
  const result = structuredClone(payload);
  const disclosures: string[] = [];

  for (const parts of normalizeDisclosablePaths(disclosable)) {
    // Own-property checks only: `in` would follow inherited properties
    // (e.g. "__proto__") out of the cloned claims into shared prototypes.
    let parent: unknown = result;
    for (let i = 0; i < parts.length; i++) {
      if (Array.isArray(parent)) {
        throw new Error(
          `disclosable path traverses an array (array-element disclosure is not supported): ${JSON.stringify(parts)}`,
        );
      }
      if (!isPlainObject(parent) || !Object.hasOwn(parent, parts[i])) {
        throw new Error(
          `disclosable path not found in claims: ${JSON.stringify(parts)}`,
        );
      }
      if (i < parts.length - 1) parent = parent[parts[i]];
    }
    const obj = parent as Record<string, unknown>;
    const leafKey = parts[parts.length - 1];
    const value = obj[leafKey];
    delete obj[leafKey];
    const [discB64, digest] = createDisclosure(leafKey, value);
    disclosures.push(discB64);
    if (!Array.isArray(obj._sd)) obj._sd = [];
    (obj._sd as string[]).push(digest);
  }
  return { payload: result, disclosures };
}

/** Build the issuer SD-JWT payload (with `_sd` digests) and its disclosures. */
export function buildSdJwtPayload(
  claims: Record<string, unknown>,
  options: {
    vct: string;
    disclosable?: (string | string[])[];
    cnf?: Record<string, unknown>;
  },
): { payload: Record<string, unknown>; disclosures: string[] } {
  const { payload, disclosures } = applyStructuredDisclosures(
    { ...claims, vct: options.vct },
    options.disclosable ?? [],
  );
  if (disclosures.length > 0) payload._sd_alg = "sha-256";
  if (options.cnf) payload.cnf = options.cnf;
  return { payload, disclosures };
}

/**
 * Sign a prepared SD-JWT payload and assemble the compact SD-JWT.
 *
 * `kid` names the signing verification method in the issuer's DID document
 * (e.g. `did:web:example.com#key-1`).
 */
export async function signSdJwt(
  payload: Record<string, unknown>,
  disclosures: string[],
  privateKey: CryptoKey,
  options: { alg?: string; x5c?: string[]; kid?: string } = {},
): Promise<string> {
  const alg = options.alg ?? resolveAlg(privateKey);
  const header: Record<string, unknown> = { alg, typ: SD_JWT_VC_TYP };
  if (options.kid) header.kid = options.kid;
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
  options: { vct: string; disclosable?: (string | string[])[] } & IssueOptions,
): Promise<string> {
  const { payload, disclosures } = buildSdJwtPayload(claims, {
    vct: options.vct,
    disclosable: options.disclosable,
    cnf: options.cnf,
  });
  return signSdJwt(payload, disclosures, privateKey, {
    alg: options.alg,
    x5c: options.x5c,
    kid: options.kid,
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
  if (!ACCEPTED_SD_JWT_VC_TYPS.includes(result.protectedHeader.typ ?? "")) {
    throw new VerificationError(
      `Unexpected typ: expected '${SD_JWT_VC_TYP}', got '${result.protectedHeader.typ}'`,
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
