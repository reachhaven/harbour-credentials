/**
 * Verify the signed dc+sd-jwt example artifacts produced by story-sign.
 *
 * Mirror of the Python ``credentials.verify_signed_examples``. For every
 * ``<name>.sd-jwt`` under ``examples/signed/`` and ``examples/gaiax/signed/``:
 *
 *   1. Verify the issuer SD-JWT signature (verifySdJwtVc).
 *   2. If the credential carries harbour:BatchCredentialEvidence, verify the
 *      batched evidence (verifyBatchEvidence): recompute the Merkle leaf from the
 *      raw issuer payload, fold the inclusion proof, and check it against the root
 *      signed in the authorization JWT — verified against the authorizer's key.
 */

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  importP256PrivateKey,
  importP256PublicKey,
  verifySdJwtVc,
  verifyBatchEvidence,
  type JWK,
} from "./index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function findRepoRoot(): string {
  let current = resolve(__dirname);
  while (current !== dirname(current)) {
    try {
      readdirSync(join(current, "tests", "fixtures", "keys"));
      return current;
    } catch {
      // keep walking up
    }
    current = dirname(current);
  }
  return process.cwd();
}

const REPO_ROOT = findRepoRoot();
const KEYS_DIR = join(REPO_ROOT, "tests", "fixtures", "keys");

const ROLE_FILES: Record<string, string> = {
  "trust-anchor": "trust-anchor.p256.json",
  haven: "haven.p256.json",
  company: "company.p256.json",
  employee: "employee.p256.json",
  ascs: "ascs.p256.json",
};

async function loadDidToPub(): Promise<Map<string, CryptoKey>> {
  const mapping = JSON.parse(
    readFileSync(join(KEYS_DIR, "role-did-mapping.json"), "utf-8"),
  ) as Record<string, { did_ethr: string }>;
  const byDID = new Map<string, CryptoKey>();
  for (const [role, filename] of Object.entries(ROLE_FILES)) {
    const jwk: JWK = JSON.parse(readFileSync(join(KEYS_DIR, filename), "utf-8"));
    const did = mapping[role]?.did_ethr;
    if (did) byDID.set(did, await importP256PublicKey(jwk));
  }
  return byDID;
}

async function loadFallbackPub(): Promise<CryptoKey> {
  const jwk: JWK = JSON.parse(
    readFileSync(join(KEYS_DIR, "test-keypair-p256.json"), "utf-8"),
  );
  await importP256PrivateKey(jwk); // validate keypair loads
  return importP256PublicKey(jwk);
}

function rawIssuerPayload(sdJwt: string): Record<string, unknown> {
  const payloadB64 = sdJwt.split("~")[0].split(".")[1];
  return JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf-8"));
}

function batchEvidence(raw: Record<string, unknown>): Record<string, unknown> | null {
  const evidence = raw.evidence;
  if (!Array.isArray(evidence) || evidence.length === 0) return null;
  const ev = evidence[0] as Record<string, unknown>;
  let types = ev.type;
  if (typeof types === "string") types = [types];
  if (
    Array.isArray(types) &&
    types.some((t) => typeof t === "string" && t.endsWith("BatchCredentialEvidence"))
  ) {
    return ev;
  }
  return null;
}

async function main(): Promise<void> {
  const signedDirs = [
    join(REPO_ROOT, "examples", "signed"),
    join(REPO_ROOT, "examples", "gaiax", "signed"),
  ].filter((d) => existsSync(d));
  if (signedDirs.length === 0) {
    console.error("No signed/ directories found — run story-sign first.");
    process.exit(1);
  }

  const didToPub = await loadDidToPub();
  const fallbackPub = await loadFallbackPub();

  let credentials = 0;
  let batch = 0;
  let plain = 0;
  const errors: string[] = [];

  for (const signedDir of signedDirs) {
    console.log(`Verifying ${signedDir.replace(REPO_ROOT + "/", "")}/ ...`);
    const files = readdirSync(signedDir)
      .filter((f) => f.endsWith(".sd-jwt"))
      .sort();
    for (const file of files) {
      const sdJwt = readFileSync(join(signedDir, file), "utf-8").trim();
      const raw = rawIssuerPayload(sdJwt);
      const issuerDid = (raw.issuer as string) ?? "";
      const issuerPub = didToPub.get(issuerDid) ?? fallbackPub;

      try {
        await verifySdJwtVc(sdJwt, issuerPub);
      } catch (e) {
        errors.push(
          `${file}: issuer signature: ${e instanceof Error ? e.message : e}`,
        );
        continue;
      }
      credentials++;

      const evidence = batchEvidence(raw);
      if (!evidence) {
        plain++;
        console.log(`  OK (plain): ${file}`);
        continue;
      }
      const authorizer = evidence.authorizer as string;
      const authorizerPub = didToPub.get(authorizer);
      if (!authorizerPub) {
        errors.push(`${file}: no key for authorizer ${authorizer}`);
        continue;
      }
      try {
        await verifyBatchEvidence(raw, evidence, authorizerPub, {
          expectedAudience: issuerDid,
        });
      } catch (e) {
        errors.push(`${file}: batch evidence: ${e instanceof Error ? e.message : e}`);
        continue;
      }
      batch++;
      console.log(
        `  OK (batch evidence, authorizer ${authorizer.slice(-8)}): ${file}`,
      );
    }
  }

  console.log(
    `\nVerified ${credentials} credentials (${batch} with batch evidence, ${plain} plain).`,
  );
  if (errors.length > 0) {
    console.error(`\n${errors.length} FAILURES:`);
    for (const err of errors) console.error(`  - ${err}`);
    process.exit(1);
  }
  console.log("All signed examples verified.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
