/**
 * Merkle batches for passkey evidence: one WebAuthn assertion, many payloads.
 *
 * Mirrors the Python `harbour.merkle` module (`docs/specs/passkey-evidence.md` §5):
 *
 * - leaf: the payload digest, `SHA-256(JCS(payload without "evidence"/"proof"))`,
 *   which is exactly the challenge of single-payload evidence;
 * - node: `SHA-256(0x01 ‖ left ‖ right)`;
 * - a lone (odd) node is promoted unchanged, never duplicated (CVE-2012-2459);
 * - the challenge is the root, so a batch of one has an empty path and is
 *   byte-identical to single-payload evidence.
 *
 * Leaves carry no `0x00` prefix: a leaf preimage is RFC 8785 JSON text starting
 * with `{` and a node preimage is 65 bytes starting with `0x01`, so the two can
 * never be confused.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import canonicalize from "canonicalize";

/** Members left out of a payload digest. */
export const EXCLUDED_DIGEST_KEYS: readonly string[] = ["evidence", "proof"];

/** Upper bound on `merklePath` length (2^32 payloads per assertion). */
export const MAX_PATH_LENGTH = 32;

const NODE_PREFIX = Uint8Array.of(0x01);
const B64URL = /^[A-Za-z0-9_-]*$/;

/** One `merklePath` element: the sibling digest and the side it sits on. */
export interface MerklePathElement {
  hash: string;
  position: "left" | "right";
}

/** A `merklePath` that is not a well-formed list of path elements. */
export class MerklePathError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MerklePathError";
  }
}

export function b64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** Strict: padding or characters outside the base64url alphabet fail. */
export function b64urlDecode(text: string): Uint8Array {
  if (typeof text !== "string" || !B64URL.test(text) || text.length % 4 === 1) {
    throw new TypeError("not base64url");
  }
  return new Uint8Array(Buffer.from(text, "base64url"));
}

function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

/** `SHA-256(UTF-8(JCS(payload without evidence/proof)))`: the leaf and the
 * single-payload challenge. */
export function payloadDigestBytes(payload: Record<string, unknown>): Uint8Array {
  const signed = Object.fromEntries(
    Object.entries(payload).filter(([k]) => !EXCLUDED_DIGEST_KEYS.includes(k)),
  );
  const canonical = canonicalize(signed);
  if (canonical === undefined) {
    throw new TypeError("payload has no JSON representation");
  }
  return sha256(new TextEncoder().encode(canonical));
}

/** `SHA-256(0x01 ‖ left ‖ right)`. */
export function hashNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(NODE_PREFIX, left, right);
}

function buildLevels(leaves: Uint8Array[]): Uint8Array[][] {
  if (leaves.length === 0) {
    throw new Error("cannot build a Merkle tree over an empty batch");
  }
  const levels = [[...leaves]];
  while (levels[levels.length - 1].length > 1) {
    const current = levels[levels.length - 1];
    const next: Uint8Array[] = [];
    for (let i = 0; i + 1 < current.length; i += 2) {
      next.push(hashNode(current[i], current[i + 1]));
    }
    if (current.length % 2) next.push(current[current.length - 1]);
    levels.push(next);
  }
  return levels;
}

/** The Merkle root over `leaves` (raw 32 bytes). */
export function merkleRoot(leaves: Uint8Array[]): Uint8Array {
  const levels = buildLevels(leaves);
  return levels[levels.length - 1][0];
}

/** The `merklePath` of the leaf at `index`. */
export function inclusionPath(
  leaves: Uint8Array[],
  index: number,
): MerklePathElement[] {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new RangeError(
      `leaf index ${index} out of range for batch of ${leaves.length}`,
    );
  }
  const levels = buildLevels(leaves);
  const path: MerklePathElement[] = [];
  let idx = index;
  for (const level of levels.slice(0, -1)) {
    if (idx % 2 === 0) {
      if (idx + 1 < level.length) {
        path.push({ hash: b64urlEncode(level[idx + 1]), position: "right" });
      }
    } else {
      path.push({ hash: b64urlEncode(level[idx - 1]), position: "left" });
    }
    idx = Math.floor(idx / 2);
  }
  return path;
}

/**
 * Fold `leaf` up `path` and return the root it commits to. An absent path
 * (`undefined` or `null`) or `[]` is the path of a batch of one. Throws
 * `MerklePathError` on a malformed path.
 */
export function foldPath(leaf: Uint8Array, path: unknown): Uint8Array {
  if (path === undefined || path === null) return leaf;
  if (!Array.isArray(path)) throw new MerklePathError("merklePath must be a list");
  if (path.length > MAX_PATH_LENGTH) {
    throw new MerklePathError(`merklePath longer than ${MAX_PATH_LENGTH}`);
  }
  let acc = leaf;
  for (const step of path) {
    if (!step || typeof step !== "object" || Array.isArray(step)) {
      throw new MerklePathError("merklePath element must be an object");
    }
    const { hash, position } = step as Record<string, unknown>;
    let sibling: Uint8Array;
    try {
      sibling = b64urlDecode(hash as string);
    } catch {
      throw new MerklePathError("merklePath hash is not base64url");
    }
    if (sibling.length !== 32) {
      throw new MerklePathError("merklePath hash must be 32 bytes");
    }
    if (position === "left") acc = hashNode(sibling, acc);
    else if (position === "right") acc = hashNode(acc, sibling);
    else throw new MerklePathError(`invalid merklePath position: ${String(position)}`);
  }
  return acc;
}

/** Fold `leaf` through `path` and compare (constant time) with `root`. */
export function verifyInclusion(
  leaf: Uint8Array,
  path: unknown,
  root: Uint8Array,
): boolean {
  let folded: Uint8Array;
  try {
    folded = foldPath(leaf, path);
  } catch (e) {
    if (e instanceof MerklePathError) return false;
    throw e;
  }
  return folded.length === root.length && timingSafeEqual(folded, root);
}

/** The challenge (b64url root) and every `merklePath` for a batch of payloads. */
export function buildBatch(payloads: Record<string, unknown>[]): {
  challenge: string;
  leaves: string[];
  paths: MerklePathElement[][];
} {
  const leaves = payloads.map(payloadDigestBytes);
  return {
    challenge: b64urlEncode(merkleRoot(leaves)),
    leaves: leaves.map(b64urlEncode),
    paths: leaves.map((_, i) => inclusionPath(leaves, i)),
  };
}
