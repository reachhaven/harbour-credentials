import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  createKbJwt,
  verifyKbJwt,
  KbJwtVerificationError,
} from "../../../src/typescript/harbour/kb-jwt.js";
import { issueSdJwtVc } from "../../../src/typescript/harbour/sd-jwt.js";
import {
  importP256PrivateKey,
  importP256PublicKey,
  generateP256Keypair,
} from "../../../src/typescript/harbour/keys.js";

const FIXTURES_DIR = resolve(__dirname, "../../fixtures");

const SAMPLE_CLAIMS = {
  iss: "did:web:issuer.example.com",
  iat: Math.floor(Date.now() / 1000),
  legalName: "Test Corp",
};

const VCT = "https://example.com/credentials/v1/TestCredential";

let issuerPrivateKey: CryptoKey;
let holderPrivateKey: CryptoKey;
let holderPublicKey: CryptoKey;

beforeAll(async () => {
  const fixture = JSON.parse(
    readFileSync(resolve(FIXTURES_DIR, "keys", "test-keypair-p256.json"), "utf-8")
  );
  issuerPrivateKey = await importP256PrivateKey(fixture);

  // Generate separate holder keypair
  const holder = await generateP256Keypair();
  holderPrivateKey = holder.privateKey;
  holderPublicKey = holder.publicKey;
});

describe("KB-JWT creation", () => {
  it("appends KB-JWT to SD-JWT", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, issuerPrivateKey, { vct: VCT });

    const withKb = await createKbJwt(sdJwt, holderPrivateKey, {
      nonce: "test-nonce-123",
      audience: "did:web:verifier.example.com",
    });

    // Should have one more ~ segment than the original
    const originalParts = sdJwt.split("~").filter(Boolean);
    const newParts = withKb.split("~").filter(Boolean);
    expect(newParts.length).toBe(originalParts.length + 1);

    // Last part should be a JWT (3 parts separated by .)
    const kbJwt = newParts[newParts.length - 1];
    expect(kbJwt.split(".").length).toBe(3);
  });

  it("includes transaction_data_hashes when provided", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, issuerPrivateKey, { vct: VCT });

    const withKb = await createKbJwt(sdJwt, holderPrivateKey, {
      nonce: "test-nonce",
      audience: "did:web:verifier.example.com",
      transactionData: ["tx1", "tx2"],
    });

    // Verify and check payload
    const payload = await verifyKbJwt(withKb, holderPublicKey, {
      expectedNonce: "test-nonce",
      expectedAudience: "did:web:verifier.example.com",
      expectedTransactionData: ["tx1", "tx2"],
    });

    expect(payload.transaction_data_hashes).toBeDefined();
    expect(payload.transaction_data_hashes!.length).toBe(2);
    expect(payload.transaction_data_hashes_alg).toBe("sha-256");
  });
});

describe("KB-JWT verification", () => {
  it("verifies valid KB-JWT", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, issuerPrivateKey, { vct: VCT });
    const withKb = await createKbJwt(sdJwt, holderPrivateKey, {
      nonce: "nonce-abc",
      audience: "aud-xyz",
    });

    const payload = await verifyKbJwt(withKb, holderPublicKey, {
      expectedNonce: "nonce-abc",
      expectedAudience: "aud-xyz",
    });

    expect(payload.nonce).toBe("nonce-abc");
    expect(payload.aud).toBe("aud-xyz");
    expect(payload.sd_hash).toBeDefined();
    expect(payload.iat).toBeDefined();
  });

  it("throws on wrong nonce", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, issuerPrivateKey, { vct: VCT });
    const withKb = await createKbJwt(sdJwt, holderPrivateKey, {
      nonce: "correct-nonce",
      audience: "aud",
    });

    await expect(
      verifyKbJwt(withKb, holderPublicKey, {
        expectedNonce: "wrong-nonce",
        expectedAudience: "aud",
      })
    ).rejects.toThrow(KbJwtVerificationError);
  });

  it("throws on wrong audience", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, issuerPrivateKey, { vct: VCT });
    const withKb = await createKbJwt(sdJwt, holderPrivateKey, {
      nonce: "nonce",
      audience: "correct-aud",
    });

    await expect(
      verifyKbJwt(withKb, holderPublicKey, {
        expectedNonce: "nonce",
        expectedAudience: "wrong-aud",
      })
    ).rejects.toThrow(KbJwtVerificationError);
  });

  it("throws on wrong key", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, issuerPrivateKey, { vct: VCT });
    const withKb = await createKbJwt(sdJwt, holderPrivateKey, {
      nonce: "nonce",
      audience: "aud",
    });

    // Use a different key for verification
    const { publicKey: wrongKey } = await generateP256Keypair();

    await expect(
      verifyKbJwt(withKb, wrongKey, {
        expectedNonce: "nonce",
        expectedAudience: "aud",
      })
    ).rejects.toThrow(KbJwtVerificationError);
  });

  it("throws on transaction_data mismatch", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, issuerPrivateKey, { vct: VCT });
    const withKb = await createKbJwt(sdJwt, holderPrivateKey, {
      nonce: "nonce",
      audience: "aud",
      transactionData: ["tx1", "tx2"],
    });

    await expect(
      verifyKbJwt(withKb, holderPublicKey, {
        expectedNonce: "nonce",
        expectedAudience: "aud",
        expectedTransactionData: ["tx1", "WRONG"],
      })
    ).rejects.toThrow(KbJwtVerificationError);
  });
});
