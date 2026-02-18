import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { signVcJose, signVpJose } from "../src/signer.js";
import { verifyVcJose, verifyVpJose, VerificationError } from "../src/verifier.js";
import {
  importP256PrivateKey,
  importP256PublicKey,
  generateP256Keypair,
} from "../src/keys.js";

const FIXTURES_DIR = resolve(__dirname, "../../tests/fixtures");

let privateKey: CryptoKey;
let publicKey: CryptoKey;
let sampleVc: Record<string, unknown>;

beforeAll(async () => {
  const fixture = JSON.parse(
    readFileSync(resolve(FIXTURES_DIR, "test-keypair-p256.json"), "utf-8"),
  );
  privateKey = await importP256PrivateKey(fixture);
  publicKey = await importP256PublicKey(fixture);
  sampleVc = JSON.parse(
    readFileSync(resolve(FIXTURES_DIR, "sample-vc.json"), "utf-8"),
  );
});

describe("verifyVcJose", () => {
  it("returns the VC payload on valid signature", async () => {
    const token = await signVcJose(sampleVc, privateKey);
    const result = await verifyVcJose(token, publicKey);
    expect(result).toEqual(sampleVc);
  });

  it("throws on wrong key", async () => {
    const token = await signVcJose(sampleVc, privateKey);
    const { publicKey: wrongKey } = await generateP256Keypair();
    await expect(verifyVcJose(token, wrongKey)).rejects.toThrow(VerificationError);
  });

  it("roundtrip: sign then verify via string", async () => {
    const token = await signVcJose(sampleVc, privateKey);
    const tokenCopy = String(token);
    const result = await verifyVcJose(tokenCopy, publicKey);
    expect(result).toEqual(sampleVc);
  });
});

describe("verifyVpJose", () => {
  const sampleVp = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiablePresentation"],
    verifiableCredential: [],
  };

  it("validates nonce and audience", async () => {
    const token = await signVpJose(sampleVp, privateKey, {
      nonce: "test-nonce",
      audience: "did:web:verifier.example.com",
    });
    const result = await verifyVpJose(token, publicKey, {
      expectedNonce: "test-nonce",
      expectedAudience: "did:web:verifier.example.com",
    });
    expect(result.type).toEqual(["VerifiablePresentation"]);
    expect(result.nonce).toBe("test-nonce");
  });

  it("throws on wrong nonce", async () => {
    const token = await signVpJose(sampleVp, privateKey, { nonce: "real" });
    await expect(
      verifyVpJose(token, publicKey, { expectedNonce: "wrong" }),
    ).rejects.toThrow(VerificationError);
  });

  it("throws on wrong audience", async () => {
    const token = await signVpJose(sampleVp, privateKey, {
      audience: "did:web:real.example.com",
    });
    await expect(
      verifyVpJose(token, publicKey, { expectedAudience: "did:web:evil.example.com" }),
    ).rejects.toThrow(VerificationError);
  });

  it("skips nonce check if not expected", async () => {
    const token = await signVpJose(sampleVp, privateKey);
    const result = await verifyVpJose(token, publicKey);
    expect(result.type).toEqual(["VerifiablePresentation"]);
  });
});
