import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import {
  EVIDENCE_TYPE,
  STATEMENT_TEMPLATE,
  buildBatchEvidence,
  composeAuthorizationMessage,
  extractRootFromMessage,
  signAuthorization,
  verifyAuthorization,
  verifyBatchEvidence,
  generateP256Keypair,
  computeLeaf,
  merkleRootB64url,
  VerificationError,
} from "../../../src/typescript/harbour/index.js";

const AUTHORIZED_BY = "did:ethr:0x14a34:0xa682b9044de0a1ad3429e8c6a0be0ed45d01da93";
// The OID4VP intake verifier's client id (gatehouse did:key stand-in).
const AUDIENCE = "did:key:zDnaefrde2MxCJfVoE1Z6RW6Zk6S91ot2w2x1c9Xwm5WiBMo9";

function payload(n: number): Record<string, unknown> {
  return {
    type: ["VerifiableCredential", "harbour:NaturalPersonCredential"],
    id: `urn:uuid:0000000${n}`,
    issuer: AUTHORIZED_BY,
    vct: "https://w3id.org/reachhaven/harbour/gx/v1/NaturalPersonCredential",
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: { id: `did:ethr:0x14a34:0x${n.toString(16).padStart(40, "0")}` },
  };
}

function message(root: string, n = 1): string {
  return composeAuthorizationMessage(root, n, {
    domain: "harbour.local",
    address: AUTHORIZED_BY,
    nonce: "deadbeefdeadbeef",
    issuedAt: "2026-07-07T00:00:00+00:00",
  });
}

describe("authorization message grammar (§4.3.1)", () => {
  it("contains exactly one normative statement line and round-trips the root", () => {
    const root = merkleRootB64url([computeLeaf(payload(1))]);
    const msg = message(root, 3);
    expect(msg).toContain(STATEMENT_TEMPLATE(3, root));
    const [extracted, n] = extractRootFromMessage(msg);
    expect(extracted).toBe(root);
    expect(n).toBe(3);
  });

  it("rejects a message without a statement line", () => {
    expect(() => extractRootFromMessage("hello world\nNonce: abc")).toThrow(
      VerificationError,
    );
  });

  it("rejects a message with two statement lines", () => {
    const root = merkleRootB64url([computeLeaf(payload(1))]);
    const line = STATEMENT_TEMPLATE(1, root);
    expect(() => extractRootFromMessage(`${line}\n${line}`)).toThrow(
      VerificationError,
    );
  });
});

describe("authorization KB-JWT (§4.3)", () => {
  it("round-trips: typ kb+jwt, nonce = sha256(message), no iss/kid", async () => {
    const { privateKey, publicKey } = await generateP256Keypair();
    const root = merkleRootB64url([computeLeaf(payload(1))]);
    const msg = message(root);
    const token = await signAuthorization(msg, privateKey, {
      audience: AUDIENCE,
      iat: 1_800_000_000,
    });

    const headerB64 = token.split(".")[0];
    const header = JSON.parse(Buffer.from(headerB64, "base64url").toString());
    expect(header.typ).toBe("kb+jwt");
    expect(header.kid).toBeUndefined();

    const verified = await verifyAuthorization(token, publicKey, {
      message: msg,
      expectedAudience: AUDIENCE,
    });
    expect(verified.nonce).toBe(
      createHash("sha256").update(msg, "utf-8").digest("hex"),
    );
    expect(verified.iat).toBe(1_800_000_000);
    // KB-JWT identifies its signer by key, not by claim (§4.3).
    expect(verified.iss).toBeUndefined();
  });

  it("rejects a tampered message (nonce mismatch)", async () => {
    const { privateKey, publicKey } = await generateP256Keypair();
    const msg = message("A".repeat(43));
    const token = await signAuthorization(msg, privateKey, { audience: AUDIENCE });
    await expect(
      verifyAuthorization(token, publicKey, { message: msg + " " }),
    ).rejects.toThrow(VerificationError);
  });

  it("rejects a wrong audience", async () => {
    const { privateKey, publicKey } = await generateP256Keypair();
    const msg = message("A".repeat(43));
    const token = await signAuthorization(msg, privateKey, { audience: AUDIENCE });
    await expect(
      verifyAuthorization(token, publicKey, {
        message: msg,
        expectedAudience: "did:key:zWrong",
      }),
    ).rejects.toThrow(VerificationError);
  });
});

describe("batch evidence (§5, §6)", () => {
  it("builds and verifies an N=4 batch with one shared KB-JWT + message", async () => {
    const { privateKey, publicKey } = await generateP256Keypair();
    const payloads = [1, 2, 3, 4].map(payload);
    const evidence = await buildBatchEvidence(payloads, privateKey, {
      authorizedBy: AUTHORIZED_BY,
      audience: AUDIENCE,
    });
    expect(evidence).toHaveLength(4);
    expect(new Set(evidence.map((e) => e.authorization)).size).toBe(1);
    expect(new Set(evidence.map((e) => e.authorizationMessage)).size).toBe(1);
    const [, n] = extractRootFromMessage(evidence[0].authorizationMessage);
    expect(n).toBe(4);

    for (let i = 0; i < payloads.length; i++) {
      expect(evidence[i].type).toEqual([EVIDENCE_TYPE]);
      expect(evidence[i].authorizedBy).toBe(AUTHORIZED_BY);
      const full = { ...payloads[i], evidence: [evidence[i]] };
      const auth = await verifyBatchEvidence(
        full,
        evidence[i] as unknown as Record<string, unknown>,
        publicKey,
        { expectedAudience: AUDIENCE },
      );
      expect(auth.aud).toBe(AUDIENCE);
    }
  });

  it("N=1 degenerate batch has an empty proof path", async () => {
    const { privateKey, publicKey } = await generateP256Keypair();
    const payloads = [payload(1)];
    const evidence = await buildBatchEvidence(payloads, privateKey, {
      authorizedBy: AUTHORIZED_BY,
      audience: AUDIENCE,
    });
    expect(evidence[0].merkleProof.path).toEqual([]);
    await verifyBatchEvidence(
      payloads[0],
      evidence[0] as unknown as Record<string, unknown>,
      publicKey,
    );
  });

  it("rejects a tampered payload", async () => {
    const { privateKey, publicKey } = await generateP256Keypair();
    const payloads = [1, 2, 3, 4].map(payload);
    const evidence = await buildBatchEvidence(payloads, privateKey, {
      authorizedBy: AUTHORIZED_BY,
      audience: AUDIENCE,
    });
    const tampered = {
      ...payloads[0],
      credentialSubject: { id: "did:ethr:0x14a34:0xdeadbeef" },
    };
    await expect(
      verifyBatchEvidence(
        tampered,
        evidence[0] as unknown as Record<string, unknown>,
        publicKey,
      ),
    ).rejects.toThrow(VerificationError);
  });

  it("rejects a message whose root was swapped", async () => {
    const { privateKey, publicKey } = await generateP256Keypair();
    const payloads = [payload(1)];
    const evidence = await buildBatchEvidence(payloads, privateKey, {
      authorizedBy: AUTHORIZED_BY,
      audience: AUDIENCE,
    });
    const [realRoot] = extractRootFromMessage(evidence[0].authorizationMessage);
    const ev = {
      ...evidence[0],
      authorizationMessage: evidence[0].authorizationMessage.replace(
        realRoot,
        "B".repeat(43),
      ),
    };
    await expect(
      verifyBatchEvidence(
        payloads[0],
        ev as unknown as Record<string, unknown>,
        publicKey,
      ),
    ).rejects.toThrow(VerificationError);
  });

  it("rejects evidence missing the authorizationMessage", async () => {
    const { privateKey, publicKey } = await generateP256Keypair();
    const payloads = [payload(1)];
    const evidence = await buildBatchEvidence(payloads, privateKey, {
      authorizedBy: AUTHORIZED_BY,
      audience: AUDIENCE,
    });
    const { authorizationMessage: _m, ...ev } = evidence[0];
    await expect(
      verifyBatchEvidence(
        payloads[0],
        ev as unknown as Record<string, unknown>,
        publicKey,
      ),
    ).rejects.toThrow(VerificationError);
  });

  it("evidence is excluded from the leaf, so proofs hold after attachment", async () => {
    const { privateKey, publicKey } = await generateP256Keypair();
    const payloads = [1, 2, 3].map(payload);
    const evidence = await buildBatchEvidence(payloads, privateKey, {
      authorizedBy: AUTHORIZED_BY,
      audience: AUDIENCE,
    });
    const withEv = { ...payloads[2], evidence: [evidence[2]] };
    expect(computeLeaf(withEv)).toEqual(computeLeaf(payloads[2]));
    await verifyBatchEvidence(
      withEv,
      evidence[2] as unknown as Record<string, unknown>,
      publicKey,
      { expectedAudience: AUDIENCE },
    );
  });
});
