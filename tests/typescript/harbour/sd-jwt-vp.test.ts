/**
 * Tests for SD-JWT VP (Verifiable Presentations with selective disclosure).
 */

import { describe, expect, it, beforeAll } from "vitest";

import {
  generateP256Keypair,
  p256PublicKeyToDidKey,
} from "../../../src/typescript/harbour/keys.js";
import { issueSdJwtVc } from "../../../src/typescript/harbour/sd-jwt.js";
import {
  issueSdJwtVp,
  verifySdJwtVp,
} from "../../../src/typescript/harbour/sd-jwt-vp.js";
import { VerificationError } from "../../../src/typescript/harbour/verifier.js";

// Shared test keys
let issuerPrivate: CryptoKey;
let issuerPublic: CryptoKey;
let holderPrivate: CryptoKey;
let holderPublic: CryptoKey;
let holderDid: string;
let sampleSdJwtVc: string;

beforeAll(async () => {
  const issuerKp = await generateP256Keypair();
  issuerPrivate = issuerKp.privateKey;
  issuerPublic = issuerKp.publicKey;

  const holderKp = await generateP256Keypair();
  holderPrivate = holderKp.privateKey;
  holderPublic = holderKp.publicKey;
  holderDid = await p256PublicKeyToDidKey(holderKp.publicKey);

  // SD-JWT-VC uses flat claims
  const claims = {
    iss: "did:web:issuer.example.com",
    sub: holderDid,
    givenName: "Alice",
    familyName: "Smith",
    email: "alice@example.com",
    memberOf: "Example Organization",
    role: "member",
  };

  sampleSdJwtVc = await issueSdJwtVc(claims, issuerPrivate, {
    vct: "https://example.com/MembershipCredential",
    disclosable: ["givenName", "familyName", "email"],
  });
});

// =============================================================================
// Issue Tests
// =============================================================================

describe("issueSdJwtVp", () => {
  it("issues a basic VP with all disclosures", async () => {
    const vp = await issueSdJwtVp(sampleSdJwtVc, holderPrivate, {
      nonce: "test-nonce-123",
      audience: "did:web:verifier.example.com",
    });

    expect(vp).toContain("~");
    const parts = vp.split("~");
    // vp-jwt + issuer-jwt + 3 disclosures + kb-jwt = 6
    expect(parts.length).toBeGreaterThanOrEqual(4);

    // Check VP JWT header
    const vpHeader = JSON.parse(
      Buffer.from(parts[0].split(".")[0], "base64url").toString()
    );
    expect(vpHeader.typ).toBe("vp+sd-jwt");
    expect(vpHeader.alg).toBe("ES256");

    // Check KB-JWT header
    const kbHeader = JSON.parse(
      Buffer.from(parts[parts.length - 1].split(".")[0], "base64url").toString()
    );
    expect(kbHeader.typ).toBe("kb+jwt");
  });

  it("issues with no disclosures (max privacy)", async () => {
    const vp = await issueSdJwtVp(sampleSdJwtVc, holderPrivate, {
      disclosures: [],
      nonce: "nonce-789",
    });

    const parts = vp.split("~");
    // vp-jwt + issuer-jwt + kb-jwt = 3 (no disclosures)
    expect(parts.length).toBeGreaterThanOrEqual(3);
  });

  it("issues with evidence", async () => {
    const evidence = [
      {
        type: "DelegatedSignatureEvidence",
        transactionData: {
          type: "harbour_delegate:data.purchase",
          credential_ids: ["simpulse_id"],
          nonce: "tx-nonce",
          iat: 1771934400,
          txn: { assetId: "tx:abc123", price: "100" },
        },
        delegatedTo: "did:web:signing-service.example.com",
      },
    ];

    const vp = await issueSdJwtVp(sampleSdJwtVc, holderPrivate, {
      evidence,
      nonce: "tx-consent-nonce",
      audience: "did:web:signing-service.example.com",
    });

    // Parse VP payload to check evidence
    const parts = vp.split("~");
    const vpPayload = JSON.parse(
      Buffer.from(parts[0].split(".")[1], "base64url").toString()
    );

    expect(vpPayload.vp.evidence).toHaveLength(1);
    expect(vpPayload.vp.evidence[0].type).toBe(
      "DelegatedSignatureEvidence"
    );
  });

  it("issues with holder DID", async () => {
    const vp = await issueSdJwtVp(sampleSdJwtVc, holderPrivate, {
      holderDid,
      nonce: "holder-nonce",
    });

    const parts = vp.split("~");
    const vpPayload = JSON.parse(
      Buffer.from(parts[0].split(".")[1], "base64url").toString()
    );

    expect(vpPayload.iss).toBe(holderDid);
    expect(vpPayload.vp.holder).toBe(holderDid);
  });
});

// =============================================================================
// Verify Tests
// =============================================================================

describe("verifySdJwtVp", () => {
  it("verifies a basic VP", async () => {
    const nonce = "verify-test-nonce";
    const audience = "did:web:verifier.example.com";

    const vp = await issueSdJwtVp(sampleSdJwtVc, holderPrivate, {
      nonce,
      audience,
    });

    const result = await verifySdJwtVp(vp, issuerPublic, holderPublic, {
      expectedNonce: nonce,
      expectedAudience: audience,
    });

    expect(result.credential).toBeDefined();
    expect(result.nonce).toBe(nonce);
    expect(result.audience).toBe(audience);
  });

  it("returns disclosed claims", async () => {
    const vp = await issueSdJwtVp(sampleSdJwtVc, holderPrivate);
    const result = await verifySdJwtVp(vp, issuerPublic, holderPublic);

    // Non-SD claims
    expect(result.credential.memberOf).toBe("Example Organization");
    expect(result.credential.role).toBe("member");
    // SD claims (all disclosed)
    expect(result.credential.givenName).toBe("Alice");
    expect(result.credential.familyName).toBe("Smith");
    expect(result.credential.email).toBe("alice@example.com");
  });

  it("respects selective disclosure", async () => {
    const vp = await issueSdJwtVp(sampleSdJwtVc, holderPrivate, {
      disclosures: ["givenName"],
    });

    const result = await verifySdJwtVp(vp, issuerPublic, holderPublic);

    expect(result.credential.givenName).toBe("Alice");
    expect(result.credential.familyName).toBeUndefined();
    expect(result.credential.email).toBeUndefined();
  });

  it("returns evidence", async () => {
    const evidence = [
      {
        type: "DelegatedSignatureEvidence",
        transactionData: {
          type: "harbour_delegate:blockchain.approve",
          credential_ids: ["default"],
          nonce: "consent-nonce",
          iat: 1771934400,
          txn: { contract: "0x1234" },
        },
      },
    ];

    const vp = await issueSdJwtVp(sampleSdJwtVc, holderPrivate, { evidence });
    const result = await verifySdJwtVp(vp, issuerPublic, holderPublic);

    expect(result.evidence).toHaveLength(1);
    expect(result.evidence![0].type).toBe("DelegatedSignatureEvidence");
  });

  it("fails with wrong issuer key", async () => {
    const wrongKp = await generateP256Keypair();
    const vp = await issueSdJwtVp(sampleSdJwtVc, holderPrivate);

    await expect(
      verifySdJwtVp(vp, wrongKp.publicKey, holderPublic)
    ).rejects.toThrow(VerificationError);
  });

  it("fails with wrong holder key", async () => {
    const wrongKp = await generateP256Keypair();
    const vp = await issueSdJwtVp(sampleSdJwtVc, holderPrivate);

    await expect(
      verifySdJwtVp(vp, issuerPublic, wrongKp.publicKey)
    ).rejects.toThrow(VerificationError);
  });

  it("fails with nonce mismatch", async () => {
    const vp = await issueSdJwtVp(sampleSdJwtVc, holderPrivate, {
      nonce: "original-nonce",
    });

    await expect(
      verifySdJwtVp(vp, issuerPublic, holderPublic, {
        expectedNonce: "wrong-nonce",
      })
    ).rejects.toThrow(/Nonce mismatch/);
  });

  it("fails with audience mismatch", async () => {
    const vp = await issueSdJwtVp(sampleSdJwtVc, holderPrivate, {
      audience: "did:web:expected.example.com",
    });

    await expect(
      verifySdJwtVp(vp, issuerPublic, holderPublic, {
        expectedAudience: "did:web:wrong.example.com",
      })
    ).rejects.toThrow(/Audience mismatch/);
  });
});

// =============================================================================
// Edge Cases
// =============================================================================

describe("Edge cases", () => {
  it("rejects invalid SD-JWT-VC format", async () => {
    await expect(
      issueSdJwtVp("not-a-valid-sd-jwt", holderPrivate)
    ).rejects.toThrow("Invalid SD-JWT-VC format");
  });

  it("rejects invalid SD-JWT VP format", async () => {
    await expect(
      verifySdJwtVp("not~valid", issuerPublic, holderPublic)
    ).rejects.toThrow("Invalid SD-JWT VP format");
  });
});
