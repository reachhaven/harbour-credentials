/**
 * Tests for the harbour digest-sri module (W3C SRI digestSRI compute + verify).
 *
 * The known-answer `LEGAL_PERSON_SRI` is shared verbatim with the Python suite
 * (`tests/python/harbour/test_digest_sri.py`) to guarantee the two runtimes
 * canonicalize and hash byte-identically. The referenced VC contains non-ASCII
 * content ("München" / "Musterstraße"), which is exactly where the
 * canonicalization choice matters for parity.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  canonicalJson,
  computeDigestSri,
  parseDigestSri,
  verifyDigestSri,
  DigestSriError,
} from "../../../src/typescript/harbour/digest-sri.js";

const GAIAX = resolve(__dirname, "../../../examples/gaiax");

// Cross-runtime known-answer vector (keep in sync with the Python suite).
// Standard base64 (RFC 4648 §4) per W3C SRI — NOT lowercase hex.
const LEGAL_PERSON_SRI = "sha256-dl7zg1RuG2HhA97FckTfjuXIUxhc0Cagbp2MD4B6JTw=";

function load(name: string): unknown {
  return JSON.parse(readFileSync(resolve(GAIAX, name), "utf-8"));
}

describe("canonicalJson", () => {
  it("sorts keys with no whitespace", () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it("sorts nested keys", () => {
    expect(canonicalJson({ x: { b: 1, a: 2 } })).toBe('{"x":{"a":2,"b":1}}');
  });

  it("keeps non-ASCII verbatim (parity with Python ensure_ascii=False)", () => {
    expect(canonicalJson({ city: "München" })).toBe('{"city":"München"}');
  });
});

describe("computeDigestSri", () => {
  it("matches the cross-runtime known answer", async () => {
    expect(await computeDigestSri(load("gx-legal-person.json"))).toBe(
      LEGAL_PERSON_SRI,
    );
  });

  it("produces sha256-<standard base64> (RFC 4648 §4, not hex/base64url)", async () => {
    const sri = await computeDigestSri({ a: 1 });
    const i = sri.indexOf("-");
    const [alg, digest] = [sri.slice(0, i), sri.slice(i + 1)];
    expect(alg).toBe("sha256");
    // SHA-256 (32 bytes) -> standard base64 = 43 chars + one '=' pad.
    expect(digest).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    expect(Buffer.from(digest, "base64").length).toBe(32);
  });

  it("is independent of key order", async () => {
    expect(await computeDigestSri({ a: 1, b: 2 })).toBe(
      await computeDigestSri({ b: 2, a: 1 }),
    );
  });

  it("treats a JSON string the same as the parsed object", async () => {
    const obj = { z: 1, a: [1, 2, { k: "v" }] };
    expect(await computeDigestSri(obj)).toBe(
      await computeDigestSri(JSON.stringify(obj)),
    );
  });

  it("supports sha384 and sha512", async () => {
    expect(await computeDigestSri({ a: 1 }, "sha384")).toMatch(/^sha384-/);
    expect(await computeDigestSri({ a: 1 }, "sha512")).toMatch(/^sha512-/);
  });

  it("rejects unsupported algorithms", async () => {
    await expect(computeDigestSri({ a: 1 }, "md5")).rejects.toThrow(DigestSriError);
  });
});

describe("parseDigestSri", () => {
  it("splits algorithm and digest", () => {
    expect(parseDigestSri("sha256-abcDEF123")).toEqual({
      algorithm: "sha256",
      digest: "abcDEF123",
    });
  });

  it("throws without a separator", () => {
    expect(() => parseDigestSri("sha256")).toThrow(DigestSriError);
  });

  it("throws on an empty digest", () => {
    expect(() => parseDigestSri("sha256-")).toThrow(DigestSriError);
  });
});

describe("verifyDigestSri", () => {
  it("round-trips to true", async () => {
    const vc = load("gx-legal-person.json");
    expect(await verifyDigestSri(vc, await computeDigestSri(vc))).toBe(true);
  });

  it("accepts the known answer", async () => {
    expect(await verifyDigestSri(load("gx-legal-person.json"), LEGAL_PERSON_SRI)).toBe(
      true,
    );
  });

  it("returns false for a tampered credential", async () => {
    const vc = load("gx-legal-person.json") as Record<string, unknown>;
    const sri = await computeDigestSri(vc);
    vc.issuer = "did:ethr:0x14a34:0xdeadbeef";
    expect(await verifyDigestSri(vc, sri)).toBe(false);
  });

  it("throws on a malformed digestSRI", async () => {
    await expect(verifyDigestSri({ a: 1 }, "sha256")).rejects.toThrow(DigestSriError);
  });
});
