import { describe, it, expect } from "vitest";
import {
  derToX5c,
  x5cToDer,
  importPublicKeyFromX5c,
} from "../../../src/typescript/harbour/x509.js";
import { generateP256Keypair, p256PublicKeyToJwk } from "../../../src/typescript/harbour/keys.js";

describe("x5c encoding", () => {
  it("roundtrips DER to x5c and back", () => {
    // Sample DER bytes (mock certificate-like data)
    const mockDer1 = new Uint8Array([0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09]);
    const mockDer2 = new Uint8Array([0x30, 0x82, 0x02, 0x33, 0x30, 0x0e, 0x07, 0x0a]);

    const x5c = derToX5c([mockDer1, mockDer2]);

    expect(x5c).toHaveLength(2);
    expect(typeof x5c[0]).toBe("string");
    expect(typeof x5c[1]).toBe("string");

    const derBack = x5cToDer(x5c);

    expect(derBack).toHaveLength(2);
    expect(Array.from(derBack[0])).toEqual(Array.from(mockDer1));
    expect(Array.from(derBack[1])).toEqual(Array.from(mockDer2));
  });

  it("produces valid base64 strings", () => {
    const mockDer = new Uint8Array([0x30, 0x82, 0x01, 0x22]);
    const x5c = derToX5c([mockDer]);

    // Should be valid base64 (no URL-safe chars, has padding)
    expect(x5c[0]).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });
});

describe("importPublicKeyFromX5c", () => {
  // Note: This test requires a real X.509 certificate
  // For now we test that invalid input throws appropriately
  it("throws on invalid certificate data", async () => {
    const invalidX5c = ["not-a-valid-certificate"];

    await expect(importPublicKeyFromX5c(invalidX5c)).rejects.toThrow();
  });

  it("throws on empty x5c array", async () => {
    await expect(importPublicKeyFromX5c([])).rejects.toThrow();
  });
});
