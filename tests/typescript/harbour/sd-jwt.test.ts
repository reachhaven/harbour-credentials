import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { CompactSign } from "jose";
import { issueSdJwtVc, verifySdJwtVc } from "../../../src/typescript/harbour/sd-jwt.js";
import { VerificationError } from "../../../src/typescript/harbour/verifier.js";
import {
  importP256PrivateKey,
  importP256PublicKey,
  generateP256Keypair,
  p256PublicKeyToJwk,
} from "../../../src/typescript/harbour/keys.js";

const FIXTURES_DIR = resolve(__dirname, "../../fixtures");
const VCT =
  "https://w3id.org/reachhaven/harbour/core/v1/LegalPersonCredential";

const SAMPLE_CLAIMS = {
  iss: "did:ethr:0x14a34:0x212025b9751231b17ead53fdcaad8ddeffa0106c",
  iat: 1723972522,
  legalName: "Example Corporation GmbH",
  legalForm: "GmbH",
  countryCode: "DE",
  email: "info@example.com",
};

let privateKey: CryptoKey;
let publicKey: CryptoKey;

function joseHeader(sdJwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(sdJwt.split(".")[0], "base64url").toString());
}

/** Mint an SD-JWT with an arbitrary typ header (no disclosures). */
async function signWithTyp(typ: string): Promise<string> {
  const payload = new TextEncoder().encode(
    JSON.stringify({ ...SAMPLE_CLAIMS, vct: VCT }),
  );
  const signer = new CompactSign(payload);
  signer.setProtectedHeader({ alg: "ES256", typ });
  return (await signer.sign(privateKey)) + "~";
}

beforeAll(async () => {
  const fixture = JSON.parse(
    readFileSync(resolve(FIXTURES_DIR, "keys", "test-keypair-p256.json"), "utf-8"),
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

  it("uses the dc+sd-jwt typ header", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, { vct: VCT });
    expect(joseHeader(sdJwt).typ).toBe("dc+sd-jwt");
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
    expect(result.legalName).toBe("Example Corporation GmbH");
  });

  it("returns disclosed claims with selective disclosure", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, {
      vct: VCT,
      disclosable: ["email", "countryCode"],
    });
    const result = await verifySdJwtVc(sdJwt, publicKey);
    expect(result.email).toBe("info@example.com");
    expect(result.countryCode).toBe("DE");
    expect(result.legalName).toBe("Example Corporation GmbH");
  });

  it("throws on wrong key", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, { vct: VCT });
    const { publicKey: wrongKey } = await generateP256Keypair();
    await expect(verifySdJwtVc(sdJwt, wrongKey)).rejects.toThrow(
      VerificationError,
    );
  });

  it("accepts the legacy vc+sd-jwt typ during transition", async () => {
    const legacy = await signWithTyp("vc+sd-jwt");
    const result = await verifySdJwtVc(legacy, publicKey);
    expect(result.vct).toBe(VCT);
  });

  it("throws on an unknown typ", async () => {
    const token = await signWithTyp("JWT");
    await expect(verifySdJwtVc(token, publicKey)).rejects.toThrow(
      /Unexpected typ/,
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
