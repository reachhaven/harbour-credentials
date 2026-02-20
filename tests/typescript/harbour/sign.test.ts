import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { signVcJose, signVpJose } from "../../../src/typescript/harbour/signer.js";
import {
  importP256PrivateKey,
  importP256PublicKey,
  p256PublicKeyToDidKey,
} from "../../../src/typescript/harbour/keys.js";

const FIXTURES_DIR = resolve(__dirname, "../../fixtures");

function decodeHeader(token: string): Record<string, unknown> {
  const b64 = token.split(".")[0];
  return JSON.parse(Buffer.from(b64, "base64url").toString());
}

function decodePayload(token: string): Record<string, unknown> {
  const b64 = token.split(".")[1];
  return JSON.parse(Buffer.from(b64, "base64url").toString());
}

let privateKey: CryptoKey;
let publicKey: CryptoKey;
let sampleVc: Record<string, unknown>;
let kid: string;

beforeAll(async () => {
  const fixture = JSON.parse(
    readFileSync(resolve(FIXTURES_DIR, "test-keypair-p256.json"), "utf-8"),
  );
  privateKey = await importP256PrivateKey(fixture);
  publicKey = await importP256PublicKey(fixture);
  sampleVc = JSON.parse(
    readFileSync(resolve(FIXTURES_DIR, "sample-vc.json"), "utf-8"),
  );
  kid = await p256PublicKeyToDidKey(publicKey);
});

describe("signVcJose", () => {
  it("returns a 3-part compact JWS", async () => {
    const token = await signVcJose(sampleVc, privateKey);
    expect(token.split(".")).toHaveLength(3);
  });

  it("has correct header typ and alg", async () => {
    const token = await signVcJose(sampleVc, privateKey);
    const header = decodeHeader(token);
    expect(header.alg).toBe("ES256");
    expect(header.typ).toBe("vc+ld+jwt");
  });

  it("includes kid in header when provided", async () => {
    const token = await signVcJose(sampleVc, privateKey, { kid });
    const header = decodeHeader(token);
    expect(header.kid).toBe(kid);
  });

  it("includes x5c in header when provided", async () => {
    const fakeCert = Buffer.from("fake-cert").toString("base64");
    const token = await signVcJose(sampleVc, privateKey, { x5c: [fakeCert] });
    const header = decodeHeader(token);
    expect(header.x5c).toEqual([fakeCert]);
  });

  it("payload matches the input VC", async () => {
    const token = await signVcJose(sampleVc, privateKey);
    const payload = decodePayload(token);
    expect(payload).toEqual(sampleVc);
  });
});

describe("signVpJose", () => {
  const sampleVp = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiablePresentation"],
    verifiableCredential: [],
  };

  it("has correct header typ", async () => {
    const token = await signVpJose(sampleVp, privateKey);
    const header = decodeHeader(token);
    expect(header.typ).toBe("vp+ld+jwt");
  });

  it("includes nonce and audience in payload", async () => {
    const token = await signVpJose(sampleVp, privateKey, {
      nonce: "test-nonce",
      audience: "did:web:verifier.example.com",
    });
    const payload = decodePayload(token);
    expect(payload.nonce).toBe("test-nonce");
    expect(payload.aud).toBe("did:web:verifier.example.com");
    expect(payload.type).toEqual(["VerifiablePresentation"]);
  });
});
