/**
 * Tests for harbour delegation module.
 *
 * Tests cover:
 * - TransactionData creation and serialization (OID4VP fields)
 * - Challenge creation and parsing
 * - Hash computation determinism
 * - Challenge verification
 * - Validation
 * - Human-readable display
 * - Shared canonicalization test vectors
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  ACTION_LABELS,
  ACTION_TYPE,
  TYPE_PREFIX,
  ChallengeError,
  type TransactionData,
  computeTransactionHash,
  createDelegationChallenge,
  createTransactionData,
  getAction,
  parseDelegationChallenge,
  renderTransactionDisplay,
  toCanonicalJson,
  validateTransactionData,
  verifyChallenge,
} from "../../../src/typescript/harbour/delegation.js";

const FIXTURES_DIR = resolve(__dirname, "../../fixtures");

// =============================================================================
// TransactionData Tests
// =============================================================================

describe("TransactionData", () => {
  it("creates basic transaction data", () => {
    const tx = createTransactionData({
      action: "data.purchase",
      txn: { assetId: "urn:uuid:test", price: "100" },
    });

    expect(tx.type).toBe("harbour_delegate:data.purchase");
    expect(tx.credential_ids).toEqual(["default"]);
    expect(tx.txn).toEqual({ assetId: "urn:uuid:test", price: "100" });
    expect(tx.exp).toBeUndefined();
    expect(tx.description).toBeUndefined();
    expect(tx.transaction_data_hashes_alg).toEqual(["sha-256"]);
    expect(tx.nonce).toHaveLength(8);
    expect(typeof tx.iat).toBe("number");
  });

  it("creates with custom nonce", () => {
    const tx = createTransactionData({
      action: "data.purchase",
      txn: { assetId: "test" },
      nonce: "custom123",
    });
    expect(tx.nonce).toBe("custom123");
  });

  it("creates with custom iat", () => {
    const tx = createTransactionData({
      action: "data.purchase",
      txn: { assetId: "test" },
      iat: 1771934400,
    });
    expect(tx.iat).toBe(1771934400);
  });

  it("creates with optional fields", () => {
    const tx = createTransactionData({
      action: "data.purchase",
      txn: { assetId: "test" },
      exp: 1771935300,
      description: "Test purchase",
      credentialIds: ["simpulse_id"],
    });

    expect(tx.exp).toBe(1771935300);
    expect(tx.description).toBe("Test purchase");
    expect(tx.credential_ids).toEqual(["simpulse_id"]);
  });

  it("extracts action from type", () => {
    const tx = createTransactionData({
      action: "data.purchase",
      txn: { assetId: "test" },
    });
    expect(getAction(tx)).toBe("data.purchase");
  });
});

// =============================================================================
// Canonical JSON + Hash Tests
// =============================================================================

describe("Canonical JSON", () => {
  it("sorts keys recursively", () => {
    const tx: TransactionData = {
      type: "harbour_delegate:data.purchase",
      credential_ids: ["default"],
      nonce: "da9b1009",
      iat: 1771934400,
      txn: { zzzField: "last", aaaField: "first" },
      transaction_data_hashes_alg: ["sha-256"],
    };

    const json = toCanonicalJson(tx);

    // No whitespace
    expect(json).not.toContain(" ");
    expect(json).not.toContain("\n");

    // Keys sorted (aaaField before zzzField)
    expect(json.indexOf("aaaField")).toBeLessThan(json.indexOf("zzzField"));
  });

  it("produces deterministic hashes", async () => {
    const tx1: TransactionData = {
      type: "harbour_delegate:data.purchase",
      credential_ids: ["default"],
      nonce: "da9b1009",
      iat: 1771934400,
      txn: { assetId: "test", price: "100" },
      transaction_data_hashes_alg: ["sha-256"],
    };

    const tx2: TransactionData = { ...tx1 };

    const hash1 = await computeTransactionHash(tx1);
    const hash2 = await computeTransactionHash(tx2);

    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
    expect(hash1).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is independent of key insertion order", async () => {
    const tx1: TransactionData = {
      type: "harbour_delegate:data.purchase",
      credential_ids: ["default"],
      nonce: "da9b1009",
      iat: 1771934400,
      txn: { assetId: "test", price: "100" },
      transaction_data_hashes_alg: ["sha-256"],
    };

    const tx2: TransactionData = {
      type: "harbour_delegate:data.purchase",
      credential_ids: ["default"],
      nonce: "da9b1009",
      iat: 1771934400,
      txn: { price: "100", assetId: "test" },
      transaction_data_hashes_alg: ["sha-256"],
    };

    expect(await computeTransactionHash(tx1)).toBe(
      await computeTransactionHash(tx2)
    );
  });

  it("changes hash when data changes", async () => {
    const tx1: TransactionData = {
      type: "harbour_delegate:data.purchase",
      credential_ids: ["default"],
      nonce: "da9b1009",
      iat: 1771934400,
      txn: { assetId: "test", price: "100" },
      transaction_data_hashes_alg: ["sha-256"],
    };

    const tx2: TransactionData = {
      ...tx1,
      txn: { assetId: "test", price: "200" },
    };

    expect(await computeTransactionHash(tx1)).not.toBe(
      await computeTransactionHash(tx2)
    );
  });
});

// =============================================================================
// Shared Test Vectors
// =============================================================================

describe("Shared canonicalization vectors", () => {
  const vectorsJson = readFileSync(
    resolve(FIXTURES_DIR, "canonicalization-vectors.json"),
    "utf-8"
  );
  const { vectors } = JSON.parse(vectorsJson);

  for (const v of vectors) {
    it(`canonical JSON matches for '${v.name}'`, () => {
      const td = v.input as TransactionData;
      const canonical = toCanonicalJson(td);
      expect(canonical).toBe(v.canonical_json);
    });

    it(`SHA-256 hash matches for '${v.name}'`, async () => {
      const td = v.input as TransactionData;
      const hash = await computeTransactionHash(td);
      expect(hash).toBe(v.sha256_hash);
    });

    it(`challenge matches for '${v.name}'`, async () => {
      const td = v.input as TransactionData;
      const challenge = await createDelegationChallenge(td);
      expect(challenge).toBe(v.challenge);
    });
  }
});

// =============================================================================
// Challenge Creation / Parsing Tests
// =============================================================================

describe("createDelegationChallenge", () => {
  it("creates a valid challenge", async () => {
    const tx: TransactionData = {
      type: "harbour_delegate:data.purchase",
      credential_ids: ["default"],
      nonce: "da9b1009",
      iat: 1771934400,
      txn: { assetId: "test", price: "100" },
      transaction_data_hashes_alg: ["sha-256"],
    };

    const challenge = await createDelegationChallenge(tx);
    const parts = challenge.split(" ");

    expect(parts).toHaveLength(3);
    expect(parts[0]).toBe("da9b1009");
    expect(parts[1]).toBe("HARBOUR_DELEGATE");
    expect(parts[2]).toHaveLength(64);
  });
});

describe("parseDelegationChallenge", () => {
  it("parses a valid challenge", () => {
    const challenge = "da9b1009 HARBOUR_DELEGATE " + "a".repeat(64);
    const result = parseDelegationChallenge(challenge);

    expect(result.nonce).toBe("da9b1009");
    expect(result.actionType).toBe("HARBOUR_DELEGATE");
    expect(result.hash).toBe("a".repeat(64));
  });

  it("throws on invalid part count", () => {
    expect(() => parseDelegationChallenge("only")).toThrow(ChallengeError);
  });

  it("throws on invalid action type", () => {
    expect(() =>
      parseDelegationChallenge("da9b1009 WRONG_ACTION " + "a".repeat(64))
    ).toThrow(ChallengeError);
  });

  it("throws on invalid hash length", () => {
    expect(() =>
      parseDelegationChallenge("da9b1009 HARBOUR_DELEGATE tooshort")
    ).toThrow(ChallengeError);
  });

  it("throws on non-hex hash", () => {
    expect(() =>
      parseDelegationChallenge("da9b1009 HARBOUR_DELEGATE " + "g".repeat(64))
    ).toThrow(ChallengeError);
  });

  it("round-trips with createDelegationChallenge", async () => {
    const tx = createTransactionData({
      action: "data.purchase",
      txn: { assetId: "test" },
    });

    const challenge = await createDelegationChallenge(tx);
    const parsed = parseDelegationChallenge(challenge);

    expect(parsed.nonce).toBe(tx.nonce);
    expect(parsed.actionType).toBe(ACTION_TYPE);
    expect(parsed.hash).toBe(await computeTransactionHash(tx));
  });
});

// =============================================================================
// Challenge Verification Tests
// =============================================================================

describe("verifyChallenge", () => {
  it("verifies matching challenge", async () => {
    const tx: TransactionData = {
      type: "harbour_delegate:data.purchase",
      credential_ids: ["default"],
      nonce: "da9b1009",
      iat: 1771934400,
      txn: { assetId: "test" },
      transaction_data_hashes_alg: ["sha-256"],
    };

    const challenge = await createDelegationChallenge(tx);
    expect(await verifyChallenge(challenge, tx)).toBe(true);
  });

  it("fails for mismatched nonce", async () => {
    const tx: TransactionData = {
      type: "harbour_delegate:data.purchase",
      credential_ids: ["default"],
      nonce: "da9b1009",
      iat: 1771934400,
      txn: { assetId: "test" },
      transaction_data_hashes_alg: ["sha-256"],
    };

    const hash = await computeTransactionHash(tx);
    const challenge = `different HARBOUR_DELEGATE ${hash}`;
    expect(await verifyChallenge(challenge, tx)).toBe(false);
  });

  it("fails for mismatched hash", async () => {
    const tx: TransactionData = {
      type: "harbour_delegate:data.purchase",
      credential_ids: ["default"],
      nonce: "da9b1009",
      iat: 1771934400,
      txn: { assetId: "test" },
      transaction_data_hashes_alg: ["sha-256"],
    };

    const challenge = "da9b1009 HARBOUR_DELEGATE " + "b".repeat(64);
    expect(await verifyChallenge(challenge, tx)).toBe(false);
  });
});

// =============================================================================
// Validation Tests
// =============================================================================

describe("validateTransactionData", () => {
  it("validates a valid transaction", () => {
    const tx = createTransactionData({
      action: "data.purchase",
      txn: { assetId: "test" },
    });
    expect(() => validateTransactionData(tx)).not.toThrow();
  });

  it("throws for invalid type prefix", () => {
    const tx: TransactionData = {
      type: "wrong_prefix:data.purchase",
      credential_ids: ["default"],
      nonce: "da9b1009",
      iat: Math.floor(Date.now() / 1000),
      txn: { assetId: "test" },
      transaction_data_hashes_alg: ["sha-256"],
    };
    expect(() => validateTransactionData(tx)).toThrow(ChallengeError);
  });

  it("throws for short nonce", () => {
    const tx: TransactionData = {
      type: "harbour_delegate:data.purchase",
      credential_ids: ["default"],
      nonce: "abc",
      iat: Math.floor(Date.now() / 1000),
      txn: { assetId: "test" },
      transaction_data_hashes_alg: ["sha-256"],
    };
    expect(() => validateTransactionData(tx)).toThrow(/Nonce too short/);
  });

  it("throws for old timestamp", () => {
    const tx: TransactionData = {
      type: "harbour_delegate:data.purchase",
      credential_ids: ["default"],
      nonce: "da9b1009",
      iat: Math.floor(Date.now() / 1000) - 600,
      txn: { assetId: "test" },
      transaction_data_hashes_alg: ["sha-256"],
    };
    expect(() => validateTransactionData(tx, { maxAgeSeconds: 300 })).toThrow(
      /too old/
    );
  });

  it("throws for future timestamp", () => {
    const tx: TransactionData = {
      type: "harbour_delegate:data.purchase",
      credential_ids: ["default"],
      nonce: "da9b1009",
      iat: Math.floor(Date.now() / 1000) + 300,
      txn: { assetId: "test" },
      transaction_data_hashes_alg: ["sha-256"],
    };
    expect(() => validateTransactionData(tx)).toThrow(/future/);
  });

  it("throws for expired transaction", () => {
    const tx = createTransactionData({
      action: "data.purchase",
      txn: { assetId: "test" },
      exp: Math.floor(Date.now() / 1000) - 300,
    });
    expect(() => validateTransactionData(tx)).toThrow(/expired/);
  });
});

// =============================================================================
// Display Tests
// =============================================================================

describe("renderTransactionDisplay", () => {
  it("renders basic display", () => {
    const tx: TransactionData = {
      type: "harbour_delegate:data.purchase",
      credential_ids: ["default"],
      nonce: "da9b1009",
      iat: 1771934400,
      txn: { assetId: "urn:uuid:test", price: "100", currency: "ENVITED" },
      transaction_data_hashes_alg: ["sha-256"],
    };

    const display = renderTransactionDisplay(tx);

    expect(display).toContain("requests your authorization");
    expect(display).toContain("Purchase data asset");
    expect(display).toContain("da9b1009");
  });

  it("renders all known action labels", () => {
    for (const [action, label] of Object.entries(ACTION_LABELS)) {
      const tx = createTransactionData({
        action,
        txn: { testField: "value" },
      });
      const display = renderTransactionDisplay(tx);
      expect(display).toContain(label);
    }
  });
});
