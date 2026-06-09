/**
 * Compute and verify `digestSRI` Subresource Integrity hashes for credentials.
 *
 * A `digestSRI` binds a Gaia-X compliance credential to the verifiable
 * credentials it references (`harbour.gx:CompliantCredentialReference`), so a
 * verifier can confirm a referenced credential has not been modified. The value
 * follows the W3C Subresource Integrity [SRI] string form `<algorithm>-<digest>`.
 *
 * Per the W3C Subresource Integrity [SRI] specification, `<digest>` is the
 * **standard base64** encoding (RFC 4648 §4 — the `+`/`/` alphabet with `=`
 * padding, *not* base64url) of the binary hash, and the grammar is exactly
 * `hash-algorithm "-" base64-value` (e.g. `sha256-t2S5kF1q...=`). W3C VC Data
 * Model 2.0 (the `sriString` datatype, §B.3.1) and the Gaia-X Compliance Document
 * 25.10 §10 both defer to [SRI] for this format.
 *
 * NOTE — encoding compliance: some third-party / earlier-example credentials used
 * lowercase *hex* (e.g. `sha256-29784869...`). Hex is **not** SRI-compliant; this
 * module emits and verifies the standards-correct base64 form.
 *
 * W3C SRI hashes the raw bytes of the referenced resource. Harbour defines that
 * "resource" as the **canonical JSON** of the referenced credential — keys sorted
 * recursively, no insignificant whitespace, UTF-8, non-ASCII kept verbatim
 * (RFC 8785 / JCS style) — byte-identical to the Python
 * `harbour.digest_sri.canonical_json` helper, so credential content such as
 * `"München"` hashes the same in both runtimes.
 *
 * [SRI]   W3C Subresource Integrity — https://www.w3.org/TR/SRI/ (§3.1, §3.2)
 * [VCDM2] W3C VC Data Model 2.0 — sriString (§B.3.1), Integrity of Related
 *         Resources (§5.3).
 */

import canonicalize from "canonicalize";

/** SRI hash algorithm tokens permitted by W3C Subresource Integrity. */
export type SriAlgorithm = "sha256" | "sha384" | "sha512";

const SUBTLE_ALG: Record<SriAlgorithm, string> = {
  sha256: "SHA-256",
  sha384: "SHA-384",
  sha512: "SHA-512",
};

/** Raised when a digestSRI string is malformed or uses an unsupported algorithm. */
export class DigestSriError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DigestSriError";
  }
}

/**
 * Return the RFC 8785 (JCS) canonical JSON serialization used for digestSRI
 * hashing.
 *
 * Backed by the `canonicalize` library (RFC 8785). RFC 8785 is a deterministic
 * spec, so this is byte-identical to the Python `rfc8785` output — credential
 * content such as `"München"` hashes the same in both runtimes.
 */
export function canonicalJson(credential: unknown): string {
  const out = canonicalize(credential);
  if (out === undefined) {
    throw new DigestSriError("value is not JSON-serializable");
  }
  return out;
}

function normalizeAlg(algorithm: string): SriAlgorithm {
  const alg = algorithm.toLowerCase().replace(/-/g, "");
  if (alg === "sha256" || alg === "sha384" || alg === "sha512") {
    return alg;
  }
  throw new DigestSriError(
    `unsupported hash algorithm '${algorithm}'; expected sha256, sha384, or sha512`,
  );
}

/** Standard base64 (RFC 4648 §4, with `=` padding) of a digest buffer. */
function toBase64(buffer: ArrayBuffer): string {
  return Buffer.from(new Uint8Array(buffer)).toString("base64");
}

/**
 * Compute the `digestSRI` value for a credential.
 *
 * @param credential A credential object, or a JSON string (parsed first, so an
 *   embedded credential string and its parsed object yield the same digest).
 * @param algorithm SRI hash algorithm token (default `sha256`).
 * @returns The SRI string `"<algorithm>-<base64-digest>"` (standard base64 per
 *   W3C SRI / RFC 4648 §4, with `=` padding).
 */
export async function computeDigestSri(
  credential: unknown,
  algorithm: SriAlgorithm | string = "sha256",
): Promise<string> {
  const alg = normalizeAlg(algorithm);
  const obj =
    typeof credential === "string" ? JSON.parse(credential) : credential;
  const data = new TextEncoder().encode(canonicalJson(obj));
  const digest = await crypto.subtle.digest(SUBTLE_ALG[alg], data);
  return `${alg}-${toBase64(digest)}`;
}

/**
 * Split a digestSRI string into its algorithm token and base64 digest.
 * (Standard base64 contains no `-`, so the algorithm is everything before the
 * first `-` and the digest is the remainder.)
 *
 * @throws {DigestSriError} if the string is malformed or the algorithm is
 *   unsupported.
 */
export function parseDigestSri(digestSri: string): {
  algorithm: SriAlgorithm;
  digest: string;
} {
  if (typeof digestSri !== "string" || !digestSri.includes("-")) {
    throw new DigestSriError(`malformed digestSRI: ${JSON.stringify(digestSri)}`);
  }
  const idx = digestSri.indexOf("-");
  const algorithm = normalizeAlg(digestSri.slice(0, idx));
  const digest = digestSri.slice(idx + 1);
  if (!digest) {
    throw new DigestSriError(`malformed digestSRI (empty digest): ${digestSri}`);
  }
  return { algorithm, digest };
}

/** Constant-time comparison of two equal-purpose base64 digest strings. */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Return `true` iff `credential` matches the integrity hash `digestSri`.
 *
 * The digest is recomputed using the algorithm named in `digestSri` and
 * compared in constant time.
 *
 * @throws {DigestSriError} if `digestSri` is malformed.
 */
export async function verifyDigestSri(
  credential: unknown,
  digestSri: string,
): Promise<boolean> {
  const { algorithm, digest } = parseDigestSri(digestSri);
  const actual = await computeDigestSri(credential, algorithm);
  const { digest: actualDigest } = parseDigestSri(actual);
  // base64 is case-sensitive (RFC 4648 §4); compare verbatim in constant time.
  return constantTimeEqual(actualDigest, digest);
}
