/**
 * Verify the `digestSRI` integrity hashes in the Gaia-X examples (TypeScript).
 *
 * Mirrors the Python `credentials.digest_sri_examples --check` step: each
 * `harbour.gx:CompliantCredentialReference` in the example credentials must
 * carry a `harbour.gx:digestSRI` that matches the source-of-truth input VC
 * (and its inline `harbour.gx:embeddedCredential`, when present), recomputed
 * with the real `verifyDigestSri` function.
 *
 * Run via `yarn story:digests` (invoked by `make story ts`).
 */

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyDigestSri, computeDigestSri } from "./index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function findRepoRoot(): string {
  let current = resolve(__dirname);
  while (current !== dirname(current)) {
    try {
      readdirSync(join(current, "tests", "fixtures", "keys"));
      return current;
    } catch {
      // not found, go up
    }
    current = dirname(current);
  }
  return process.cwd();
}

const REPO_ROOT = findRepoRoot();
const GAIAX_DIR = join(REPO_ROOT, "examples", "gaiax");

// credentialType -> input VC filename (the source of truth).
const INPUT_FILES: Record<string, string> = {
  "gx:LegalPerson": "gx-legal-person.json",
  "gx:VatID": "gx-registration-number.json",
  "gx:Issuer": "gx-terms-and-conditions.json",
};

const CREDENTIAL_TYPE_KEY = "harbour.gx:credentialType";
const DIGEST_KEY = "harbour.gx:digestSRI";
const EMBEDDED_KEY = "harbour.gx:embeddedCredential";

type Json = Record<string, unknown>;

function loadInputVcs(): Record<string, Json> {
  const inputs: Record<string, Json> = {};
  for (const [credentialType, filename] of Object.entries(INPUT_FILES)) {
    const path = join(GAIAX_DIR, filename);
    if (!existsSync(path)) {
      throw new Error(`Missing source-of-truth input VC: ${path}`);
    }
    inputs[credentialType] = JSON.parse(readFileSync(path, "utf-8"));
  }
  return inputs;
}

/** Collect every CompliantCredentialReference object anywhere in `node`. */
function collectReferences(node: unknown, out: Json[]): void {
  if (Array.isArray(node)) {
    for (const item of node) collectReferences(item, out);
  } else if (node !== null && typeof node === "object") {
    const obj = node as Json;
    if (CREDENTIAL_TYPE_KEY in obj && DIGEST_KEY in obj) {
      out.push(obj);
    }
    for (const value of Object.values(obj)) collectReferences(value, out);
  }
}

function targetFiles(): string[] {
  const inputNames = new Set(Object.values(INPUT_FILES));
  return readdirSync(GAIAX_DIR)
    .filter((f) => f.endsWith(".json") && !inputNames.has(f))
    .sort()
    .map((f) => join(GAIAX_DIR, f));
}

async function main(): Promise<void> {
  if (!existsSync(GAIAX_DIR)) {
    throw new Error(`gaiax examples directory not found: ${GAIAX_DIR}`);
  }
  const inputs = loadInputVcs();
  const errors: string[] = [];
  let totalRefs = 0;

  console.log(`  Verifying digestSRI hashes in ${GAIAX_DIR}/`);

  for (const path of targetFiles()) {
    const obj = JSON.parse(readFileSync(path, "utf-8"));
    const refs: Json[] = [];
    collectReferences(obj, refs);
    if (refs.length === 0) continue;
    totalRefs += refs.length;

    const fileErrors: string[] = [];
    for (const ref of refs) {
      const credentialType = ref[CREDENTIAL_TYPE_KEY] as string;
      const stored = ref[DIGEST_KEY] as string;
      const sourceVc = inputs[credentialType];
      if (!sourceVc) {
        fileErrors.push(`unknown credentialType '${credentialType}'`);
        continue;
      }
      // The digest must match the source-of-truth input VC.
      if (!(await verifyDigestSri(sourceVc, stored))) {
        fileErrors.push(
          `${credentialType} digestSRI does not match ${INPUT_FILES[credentialType]}\n` +
            `      stored:   ${stored}\n` +
            `      expected: ${await computeDigestSri(sourceVc)}`,
        );
        continue;
      }
      const embedded = ref[EMBEDDED_KEY];
      if (typeof embedded === "string") {
        let embeddedVc: unknown;
        try {
          embeddedVc = JSON.parse(embedded);
        } catch (e) {
          fileErrors.push(`${credentialType} embeddedCredential is not valid JSON`);
          continue;
        }
        if (!(await verifyDigestSri(embeddedVc, stored))) {
          fileErrors.push(
            `${credentialType} embeddedCredential content does not match its digestSRI (${stored})`,
          );
        }
      }
    }

    const name = basename(path);
    console.log(
      `    [${fileErrors.length ? "FAIL" : "ok"}] ${name} (${refs.length} reference(s))`,
    );
    errors.push(...fileErrors.map((e) => `${name}: ${e}`));
  }

  if (errors.length > 0) {
    console.error(`\nFAIL: ${errors.length} digestSRI mismatch(es):`);
    for (const err of errors) console.error(`  - ${err}`);
    console.error(
      "\nRun `python -m credentials.digest_sri_examples --write` to repair.",
    );
    process.exit(1);
  }

  console.log(`\nOK: ${totalRefs} digestSRI reference(s) verified.`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
