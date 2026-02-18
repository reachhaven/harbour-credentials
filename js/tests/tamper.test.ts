import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { signVcJose } from "../src/signer.js";
import { verifyVcJose, VerificationError } from "../src/verifier.js";
import { importP256PrivateKey, importP256PublicKey } from "../src/keys.js";

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

describe("tamper detection", () => {
  it("detects payload tampering", async () => {
    const token = await signVcJose(sampleVc, privateKey);
    const parts = token.split(".");

    // Decode, tamper, re-encode payload
    const payload = JSON.parse(
      Buffer.from(parts[1], "base64url").toString(),
    ) as Record<string, any>;
    (payload.credentialSubject as any).id =
      "did:web:did.ascs.digital:participants:evil";
    const tampered = Buffer.from(JSON.stringify(payload)).toString("base64url");

    const tamperedToken = `${parts[0]}.${tampered}.${parts[2]}`;
    await expect(verifyVcJose(tamperedToken, publicKey)).rejects.toThrow(
      VerificationError,
    );
  });

  it("detects signature corruption", async () => {
    const token = await signVcJose(sampleVc, privateKey);
    const parts = token.split(".");

    const sig = parts[2];
    const corrupted = sig.slice(0, -1) + (sig.endsWith("A") ? "B" : "A");
    const tamperedToken = `${parts[0]}.${parts[1]}.${corrupted}`;

    await expect(verifyVcJose(tamperedToken, publicKey)).rejects.toThrow(
      VerificationError,
    );
  });

  it("detects header tampering", async () => {
    const token = await signVcJose(sampleVc, privateKey);
    const parts = token.split(".");

    const header = JSON.parse(
      Buffer.from(parts[0], "base64url").toString(),
    );
    header.kid = "did:web:evil.example.com#key-1";
    const tampered = Buffer.from(JSON.stringify(header)).toString("base64url");

    const tamperedToken = `${tampered}.${parts[1]}.${parts[2]}`;
    await expect(verifyVcJose(tamperedToken, publicKey)).rejects.toThrow(
      VerificationError,
    );
  });
});
