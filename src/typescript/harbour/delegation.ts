/**
 * Harbour Delegated Signing Evidence.
 *
 * Implements the Harbour Delegated Signing Evidence Specification v2
 * for creating and verifying delegation challenges used in VP proof.challenge fields.
 *
 * The challenge format is: <nonce> HARBOUR_DELEGATE <sha256-hash>
 *
 * Where the hash is computed over a canonical JSON representation of the
 * OID4VP-aligned transaction data object (§8.4).
 */

/** Action type identifier. */
export const ACTION_TYPE = "HARBOUR_DELEGATE";

/** Type prefix for transaction data. */
export const TYPE_PREFIX = "harbour_delegate";

/** Human-friendly labels for action types. */
export const ACTION_LABELS: Record<string, string> = {
  "blockchain.transfer": "Transfer tokens",
  "blockchain.approve": "Approve token spending",
  "blockchain.execute": "Execute smart contract",
  "blockchain.sign": "Sign blockchain message",
  "contract.sign": "Sign contract",
  "contract.accept": "Accept agreement",
  "contract.reject": "Reject agreement",
  "data.purchase": "Purchase data asset",
  "data.share": "Share data",
  "data.access": "Access data",
  "credential.issue": "Issue credential",
  "credential.revoke": "Revoke credential",
  "credential.present": "Present credential",
};

/** Error parsing or validating a delegation challenge. */
export class ChallengeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChallengeError";
  }
}

/** OID4VP-aligned transaction data object for delegated signing. */
export interface TransactionData {
  /** Transaction data type identifier (harbour_delegate:<action>). */
  type: string;
  /** References to DCQL Credential Query id fields. */
  credential_ids: string[];
  /** Unique identifier for replay protection. */
  nonce: string;
  /** Issued-at Unix timestamp (seconds since epoch). */
  iat: number;
  /** Action-specific transaction details. */
  txn: Record<string, unknown>;
  /** Optional expiration Unix timestamp. */
  exp?: number;
  /** Optional human-readable description. */
  description?: string;
  /** Hash algorithms supported (default: ["sha-256"]). */
  transaction_data_hashes_alg?: string[];
}

/**
 * Extract the action from the type field.
 *
 * E.g., "harbour_delegate:data.purchase" -> "data.purchase"
 */
export function getAction(td: TransactionData): string {
  const idx = td.type.indexOf(":");
  return idx >= 0 ? td.type.slice(idx + 1) : td.type;
}

/**
 * Convert TransactionData to a plain object, omitting undefined values.
 */
function toDict(td: TransactionData): Record<string, unknown> {
  const d: Record<string, unknown> = {
    type: td.type,
    credential_ids: td.credential_ids,
    nonce: td.nonce,
    iat: td.iat,
    txn: td.txn,
  };
  if (td.exp !== undefined) d.exp = td.exp;
  if (td.description !== undefined) d.description = td.description;
  if (td.transaction_data_hashes_alg !== undefined)
    d.transaction_data_hashes_alg = td.transaction_data_hashes_alg;
  return d;
}

/**
 * Recursively sort all keys in a JSON-serializable value.
 *
 * Python's json.dumps(sort_keys=True) sorts ALL keys recursively.
 * JavaScript JSON.stringify does NOT sort keys by default and does NOT
 * accept a replacer that recursively sorts. This function creates a
 * new object/array structure with sorted keys at every level.
 */
function sortKeysRecursive(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(sortKeysRecursive);
  if (typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysRecursive(
        (value as Record<string, unknown>)[key]
      );
    }
    return sorted;
  }
  return value;
}

/**
 * Convert TransactionData to canonical JSON string.
 *
 * Matches Python's json.dumps(sort_keys=True, separators=(',', ':'))
 * which sorts ALL keys recursively with no whitespace.
 */
export function toCanonicalJson(td: TransactionData): string {
  const dict = toDict(td);
  return JSON.stringify(sortKeysRecursive(dict));
}

/**
 * Compute SHA-256 hash of TransactionData canonical JSON.
 *
 * @returns Lowercase hex-encoded SHA-256 hash (64 characters).
 */
export async function computeTransactionHash(
  td: TransactionData
): Promise<string> {
  const canonical = toCanonicalJson(td);
  const encoder = new TextEncoder();
  const data = encoder.encode(canonical);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = new Uint8Array(hashBuffer);
  return Array.from(hashArray)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Create a Harbour delegation challenge string.
 *
 * Format: <nonce> HARBOUR_DELEGATE <sha256-hash>
 */
export async function createDelegationChallenge(
  td: TransactionData
): Promise<string> {
  const hash = await computeTransactionHash(td);
  return `${td.nonce} ${ACTION_TYPE} ${hash}`;
}

/**
 * Parse a Harbour delegation challenge string.
 *
 * @returns Object with nonce, actionType, and hash.
 * @throws ChallengeError if the format is invalid.
 */
export function parseDelegationChallenge(challenge: string): {
  nonce: string;
  actionType: string;
  hash: string;
} {
  const parts = challenge.split(" ");
  if (parts.length !== 3) {
    throw new ChallengeError(
      `Invalid challenge format: expected 3 space-separated parts, got ${parts.length}`
    );
  }

  const [nonce, actionType, hash] = parts;

  if (actionType !== ACTION_TYPE) {
    throw new ChallengeError(
      `Invalid action type: expected '${ACTION_TYPE}', got '${actionType}'`
    );
  }

  if (hash.length !== 64) {
    throw new ChallengeError(
      `Invalid hash length: expected 64 hex characters, got ${hash.length}`
    );
  }

  // Validate hex
  if (!/^[0-9a-f]{64}$/.test(hash)) {
    throw new ChallengeError("Invalid hash: not valid hexadecimal");
  }

  return { nonce, actionType, hash };
}

/**
 * Verify that a challenge matches transaction data.
 *
 * @returns true if the hash in the challenge matches the transaction data.
 */
export async function verifyChallenge(
  challenge: string,
  td: TransactionData
): Promise<boolean> {
  const { nonce, hash: challengeHash } = parseDelegationChallenge(challenge);

  if (nonce !== td.nonce) return false;

  const computedHash = await computeTransactionHash(td);
  return challengeHash === computedHash;
}

/**
 * Create a new TransactionData object.
 */
export function createTransactionData(options: {
  action: string;
  txn: Record<string, unknown>;
  credentialIds?: string[];
  nonce?: string;
  iat?: number;
  exp?: number;
  description?: string;
}): TransactionData {
  const nonce =
    options.nonce ??
    Array.from(crypto.getRandomValues(new Uint8Array(4)))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

  return {
    type: `${TYPE_PREFIX}:${options.action}`,
    credential_ids: options.credentialIds ?? ["default"],
    nonce,
    iat: options.iat ?? Math.floor(Date.now() / 1000),
    txn: options.txn,
    ...(options.exp !== undefined ? { exp: options.exp } : {}),
    ...(options.description !== undefined
      ? { description: options.description }
      : {}),
    transaction_data_hashes_alg: ["sha-256"],
  };
}

/**
 * Render transaction data for human-readable display.
 */
export function renderTransactionDisplay(
  td: TransactionData,
  serviceName = "Harbour Signing Service"
): string {
  const action = getAction(td);
  const actionLabel =
    ACTION_LABELS[action] ??
    action
      .replace(/\./g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());

  const lines: string[] = [
    `${serviceName} requests your authorization`,
    "\u2500".repeat(50),
    "",
    `  Action:      ${actionLabel}`,
  ];

  for (const [key, value] of Object.entries(td.txn)) {
    const displayKey = key
      .replace(/_/g, " ")
      .replace(/Id/g, " ID")
      .replace(/\b\w/g, (c) => c.toUpperCase());
    let displayValue = String(value);
    if (displayValue.length > 40) {
      displayValue = displayValue.slice(0, 37) + "...";
    }
    lines.push(`  ${displayKey}:  ${displayValue}`);
  }

  lines.push("", "\u2500".repeat(50), `  Nonce:       ${td.nonce}`, `  Issued at:   ${td.iat}`);

  if (td.exp !== undefined) {
    lines.push(`  Expires:     ${td.exp}`);
  }

  if (td.description) {
    lines.push(`  Details:     ${td.description}`);
  }

  return lines.join("\n");
}

/**
 * Validate transaction data for security requirements.
 *
 * @throws ChallengeError if validation fails.
 */
export function validateTransactionData(
  td: TransactionData,
  options?: { maxAgeSeconds?: number }
): void {
  const maxAge = options?.maxAgeSeconds ?? 300;

  if (!td.type.startsWith(`${TYPE_PREFIX}:`)) {
    throw new ChallengeError(
      `Invalid type: expected '${TYPE_PREFIX}:*', got '${td.type}'`
    );
  }

  if (td.nonce.length < 8) {
    throw new ChallengeError(
      `Nonce too short: ${td.nonce.length} chars (minimum 8)`
    );
  }

  const now = Math.floor(Date.now() / 1000);
  const age = now - td.iat;

  if (age > maxAge) {
    throw new ChallengeError(
      `Transaction too old: ${age}s (max ${maxAge}s)`
    );
  }

  if (age < -60) {
    throw new ChallengeError(
      `Transaction timestamp is in the future: iat=${td.iat}`
    );
  }

  if (td.exp !== undefined && now > td.exp) {
    throw new ChallengeError(`Transaction expired at ${td.exp}`);
  }
}
