/**
 * Merkle tree for batched credential evidence.
 *
 * Mirror of `harbour/merkle.py` — the commitment construction from
 * `docs/specs/batched-credential-evidence.md` §4:
 *
 *   - leaf  = SHA-256( 0x00 || JCS(credential without "evidence"/"proof") )
 *   - node  = SHA-256( 0x01 || left || right )
 *   - a lone (odd) node is promoted unchanged (never duplicated, closing
 *     CVE-2012-2459)
 *   - the root is base64url (no padding) and is carried in the statement line
 *     of the authorization message, whose SHA-256 hex is the KB-JWT `nonce`
 *     (spec §4.3.1).
 *
 * The `canonicalJson` (RFC 8785 / JCS) used here is byte-identical to the
 * Python `canonical_json`, so leaves and roots match across runtimes.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { canonicalJson } from "./digest-sri.js";

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);
const EXCLUDED_LEAF_KEYS = new Set(["evidence", "proof"]);

export interface MerkleProofStep {
  hash: string;
  position: "left" | "right";
}

export function b64urlEncode(data: Buffer | Uint8Array): string {
  return Buffer.from(data).toString("base64url").replace(/=+$/, "");
}

export function b64urlDecode(value: string): Buffer {
  return Buffer.from(value, "base64url");
}

function sha256(...chunks: (Buffer | Uint8Array)[]): Buffer {
  const h = createHash("sha256");
  for (const c of chunks) h.update(c);
  return h.digest();
}

/** Leaf hash for a credential: SHA-256(0x00 || JCS(payload without evidence/proof)). */
export function computeLeaf(credential: Record<string, unknown>): Buffer {
  const payload: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(credential)) {
    if (!EXCLUDED_LEAF_KEYS.has(k)) payload[k] = v;
  }
  return sha256(LEAF_PREFIX, Buffer.from(canonicalJson(payload), "utf-8"));
}

/** Internal-node hash: SHA-256(0x01 || left || right). */
export function hashNode(left: Buffer, right: Buffer): Buffer {
  return sha256(NODE_PREFIX, left, right);
}

function buildLevels(leaves: Buffer[]): Buffer[][] {
  if (leaves.length === 0) {
    throw new Error("cannot build a Merkle tree over an empty batch");
  }
  const levels: Buffer[][] = [[...leaves]];
  while (levels[levels.length - 1].length > 1) {
    const current = levels[levels.length - 1];
    const next: Buffer[] = [];
    let i = 0;
    while (i < current.length) {
      if (i + 1 < current.length) {
        next.push(hashNode(current[i], current[i + 1]));
        i += 2;
      } else {
        next.push(current[i]); // lone node promoted, never duplicated
        i += 1;
      }
    }
    levels.push(next);
  }
  return levels;
}

export function merkleRoot(leaves: Buffer[]): Buffer {
  const levels = buildLevels(leaves);
  return levels[levels.length - 1][0];
}

export function merkleRootB64url(leaves: Buffer[]): string {
  return b64urlEncode(merkleRoot(leaves));
}

export function inclusionProof(leaves: Buffer[], index: number): MerkleProofStep[] {
  if (index < 0 || index >= leaves.length) {
    throw new Error(`leaf index ${index} out of range for batch of ${leaves.length}`);
  }
  const levels = buildLevels(leaves);
  const proof: MerkleProofStep[] = [];
  let idx = index;
  for (let level = 0; level < levels.length - 1; level++) {
    const nodes = levels[level];
    if (idx % 2 === 0) {
      const sibling = idx + 1;
      if (sibling < nodes.length) {
        proof.push({ hash: b64urlEncode(nodes[sibling]), position: "right" });
      }
      // else: lone node promoted at this level — no proof element
    } else {
      proof.push({ hash: b64urlEncode(nodes[idx - 1]), position: "left" });
    }
    idx = Math.floor(idx / 2);
  }
  return proof;
}

export function verifyInclusion(
  leaf: Buffer,
  proof: MerkleProofStep[],
  root: Buffer,
): boolean {
  let acc = leaf;
  for (const step of proof) {
    const sibling = b64urlDecode(step.hash);
    if (step.position === "left") {
      acc = hashNode(sibling, acc);
    } else if (step.position === "right") {
      acc = hashNode(acc, sibling);
    } else {
      throw new Error(`invalid proof position: ${step.position}`);
    }
  }
  return acc.length === root.length && timingSafeEqual(acc, root);
}

export function buildBatch(credentials: Record<string, unknown>[]): {
  root: string;
  leaves: string[];
  proofs: MerkleProofStep[][];
} {
  const leaves = credentials.map(computeLeaf);
  return {
    root: b64urlEncode(merkleRoot(leaves)),
    leaves: leaves.map((l) => b64urlEncode(l)),
    proofs: leaves.map((_, i) => inclusionProof(leaves, i)),
  };
}
