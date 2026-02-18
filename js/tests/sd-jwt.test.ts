import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { issueSdJwtVc, verifySdJwtVc } from "../src/sd-jwt.js";
import { VerificationError } from "../src/verifier.js";
import {
  importP256PrivateKey,
  importP256PublicKey,
  generateP256Keypair,
  p256PublicKeyToJwk,
} from "../src/keys.js";

const FIXTURES_DIR = resolve(__dirname, "../../tests/fixtures");
const VCT =
  "https://w3id.org/ascs-ev/simpulse-id/credentials/v1/ParticipantCredential";

const SAMPLE_CLAIMS = {
  iss: "did:web:did.ascs.digital:participants:ascs",
  iat: 1723972522,
  legalName: "Bayerische Motoren Werke AG",
  legalForm: "AG",
  countryCode: "DE",
  email: "imprint@bmw.com",
};

let privateKey: CryptoKey;
let publicKey: CryptoKey;

beforeAll(async () => {
  const fixture = JSON.parse(
    readFileSync(resolve(FIXTURES_DIR, "test-keypair-p256.json"), "utf-8"),
  );
  privateKey = await importP256PrivateKey(fixture);
  publicKey = await importP256PublicKey(fixture);
});

describe("SD-JWT-VC issuance", () => {
  it("produces ~-delimited format", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, { vct: VCT });
    const parts = sdJwt.split("~");
    expect(parts.length).toBeGreaterThanOrEqual(2);
    expect(parts[parts.length - 1]).toBe(""); // trailing ~
    expect(parts[0].split(".")).toHaveLength(3); // issuer JWT
  });

  it("creates disclosures for disclosable claims", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, {
      vct: VCT,
      disclosable: ["email", "countryCode"],
    });
    const parts = sdJwt.split("~");
    // issuer-jwt + 2 disclosures + trailing empty = 4 parts
    expect(parts).toHaveLength(4);
  });
});

describe("SD-JWT-VC verification", () => {
  it("returns all claims when no selective disclosure", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, { vct: VCT });
    const result = await verifySdJwtVc(sdJwt, publicKey);
    expect(result.vct).toBe(VCT);
    expect(result.legalName).toBe("Bayerische Motoren Werke AG");
  });

  it("returns disclosed claims with selective disclosure", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, {
      vct: VCT,
      disclosable: ["email", "countryCode"],
    });
    const result = await verifySdJwtVc(sdJwt, publicKey);
    expect(result.email).toBe("imprint@bmw.com");
    expect(result.countryCode).toBe("DE");
    expect(result.legalName).toBe("Bayerische Motoren Werke AG");
  });

  it("throws on wrong key", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, { vct: VCT });
    const { publicKey: wrongKey } = await generateP256Keypair();
    await expect(verifySdJwtVc(sdJwt, wrongKey)).rejects.toThrow(
      VerificationError,
    );
  });

  it("throws on VCT mismatch", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, { vct: VCT });
    await expect(
      verifySdJwtVc(sdJwt, publicKey, { expectedVct: "https://wrong.example.com" }),
    ).rejects.toThrow(VerificationError);
  });

  it("includes cnf when provided", async () => {
    const pubJwk = await p256PublicKeyToJwk(publicKey);
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, {
      vct: VCT,
      cnf: { jwk: pubJwk },
    });
    const result = await verifySdJwtVc(sdJwt, publicKey);
    expect(result.cnf).toBeDefined();
    expect((result.cnf as any).jwk.crv).toBe("P-256");
  });
});
