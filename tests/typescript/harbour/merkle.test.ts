/**
 * Tests for the Merkle batches behind batched passkey evidence. The known
 * answers in `merkle-vectors.json` are shared with the Python suite.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  b64urlEncode,
  buildBatch,
  foldPath,
  hashNode,
  inclusionPath,
  MAX_PATH_LENGTH,
  MerklePathError,
  merkleRoot,
  payloadDigestBytes,
  verifyInclusion,
} from "../../../src/typescript/harbour/merkle.js";

const VECTORS = JSON.parse(
  readFileSync(resolve(__dirname, "../../fixtures/evidence/merkle-vectors.json"), "utf-8"),
).vectors as { name: string; payloads: Record<string, unknown>[]; challenge: string; paths: unknown[] }[];

const leaves = (n: number) => Array.from({ length: n }, (_, i) => payloadDigestBytes({ i }));

describe("payload digest", () => {
  it("is SHA-256 of the JCS form without evidence and proof", () => {
    const expected = createHash("sha256").update('{"a":"x","b":1}').digest();
    expect(Buffer.from(payloadDigestBytes({ b: 1, a: "x", evidence: [1], proof: {} }))).toEqual(expected);
  });
});

describe("tree", () => {
  it("a single leaf is its own root", () => {
    const [leaf] = leaves(1);
    expect(merkleRoot([leaf])).toEqual(leaf);
    expect(inclusionPath([leaf], 0)).toEqual([]);
  });

  it("promotes the odd node instead of duplicating it", () => {
    const [a, b, c] = leaves(3);
    expect(merkleRoot([a, b, c])).toEqual(hashNode(hashNode(a, b), c));
    expect(merkleRoot([a, b, c])).not.toEqual(merkleRoot([a, b, c, c]));
  });

  it("prefixes nodes with 0x01", () => {
    const [a, b] = leaves(2);
    const expected = createHash("sha256").update(Buffer.concat([Buffer.from([1]), a, b])).digest();
    expect(Buffer.from(hashNode(a, b))).toEqual(expected);
  });

  it("folds every path to the root", () => {
    for (let n = 1; n <= 17; n++) {
      const ls = leaves(n);
      const root = merkleRoot(ls);
      for (let i = 0; i < n; i++) expect(foldPath(ls[i], inclusionPath(ls, i))).toEqual(root);
    }
  });

  it("rejects an empty batch and an out-of-range index", () => {
    expect(() => merkleRoot([])).toThrow();
    expect(() => inclusionPath(leaves(2), 2)).toThrow(RangeError);
  });
});

describe("fold", () => {
  const [leaf] = leaves(1);
  const sibling = b64urlEncode(new Uint8Array(32).fill(7));

  it("treats an absent or empty path as a batch of one", () => {
    expect(foldPath(leaf, undefined)).toEqual(leaf);
    expect(foldPath(leaf, null)).toEqual(leaf);
    expect(foldPath(leaf, [])).toEqual(leaf);
  });

  it("does not verify a wrong leaf", () => {
    const ls = leaves(4);
    expect(verifyInclusion(ls[1], inclusionPath(ls, 0), merkleRoot(ls))).toBe(false);
    expect(verifyInclusion(ls[0], inclusionPath(ls, 0), merkleRoot(ls))).toBe(true);
  });

  const malformed: [string, unknown][] = [
    ["not a list", "x"],
    ["null element", [null]],
    ["not base64url", [{ hash: "!!", position: "left" }]],
    ["31 bytes", [{ hash: b64urlEncode(new Uint8Array(31)), position: "left" }]],
    ["bad position", [{ hash: sibling, position: "up" }]],
    ["padding", [{ hash: `${sibling}=`, position: "left" }]],
    ["too long", Array(MAX_PATH_LENGTH + 1).fill({ hash: sibling, position: "left" })],
  ];
  for (const [name, path] of malformed) {
    it(`rejects a malformed path: ${name}`, () => {
      expect(() => foldPath(leaf, path)).toThrow(MerklePathError);
      expect(verifyInclusion(leaf, path, leaf)).toBe(false);
    });
  }
});

describe("known answers shared with Python", () => {
  for (const v of VECTORS) {
    it(v.name, () => {
      const batch = buildBatch(v.payloads);
      expect(batch.challenge).toBe(v.challenge);
      expect(batch.paths).toEqual(v.paths);
    });
  }
});
