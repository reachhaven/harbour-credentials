/**
 * Verify the `digestSRI` integrity hashes in the Gaia-X examples (TypeScript).
 *
 * Mirrors the Python `credentials.digest_sri_examples --check` step: each
 * `harbour.gx:CompliantCredentialReference` in the example credentials must
 * carry a `harbour.gx:digestSRI` that matches the source-of-truth input VC of
 * the owning organization — resolved by the reference's `@id` DID prefix
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

// credentialType -> input VC filename (the default source of truth,
// describing the example organization).
const INPUT_FILES: Record<string, string> = {
  "gx:LegalPerson": "gx-legal-person.json",
  "gx:VatID": "gx-registration-number.json",
  "gx:Issuer": "gx-terms-and-conditions.json",
};

// Per-organization source overrides: org DID -> { credentialType -> filename }.
// The Trust Anchor holds a normal LegalPersonCredential (ADR-006) whose
// references point at its own gx input trio rather than the default one.
const ORG_INPUT_FILES: Record<string, Record<string, string>> = {
  "did:ethr:0x14a34:0x4d6246a7d1e60caa44b75e3af9b37ac8d6442774": {
    "gx:LegalPerson": "gx-trust-anchor-legal-person.json",
    "gx:VatID": "gx-trust-anchor-registration-number.json",
    "gx:Issuer": "gx-trust-anchor-terms-and-conditions.json",
  },
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
  for (const files of Object.values(ORG_INPUT_FILES)) {
    for (const f of Object.values(files)) inputNames.add(f);
  }
  return readdirSync(GAIAX_DIR)
    .filter((f) => f.endsWith(".json") && !inputNames.has(f))
    .sort()
    .map((f) => join(GAIAX_DIR, f));
}

/**
 * Load per-organization input VCs: org DID -> { credentialType: gx VC }.
 * Mirrors `credentials.digest_sri_examples.load_org_input_vcs`.
 */
function loadOrgInputVcs(): Record<string, Record<string, Json>> {
  const sources: Record<string, Record<string, Json>> = {};
  for (const [orgDid, files] of Object.entries(ORG_INPUT_FILES)) {
    for (const [credentialType, filename] of Object.entries(files)) {
      const path = join(GAIAX_DIR, filename);
      if (!existsSync(path)) {
        throw new Error(`Missing source-of-truth input VC: ${path}`);
      }
      (sources[orgDid] ??= {})[credentialType] = JSON.parse(
        readFileSync(path, "utf-8"),
      );
    }
  }
  return sources;
}

/**
 * The gx VC a reference's digestSRI is taken over: a reference whose `@id` org
 * DID has its own input trio (ORG_INPUT_FILES) resolves to that org's gx VC;
 * otherwise to the default input VC.
 */
function resolveReferent(
  ref: Json,
  inputs: Record<string, Json>,
  orgSources: Record<string, Record<string, Json>>,
): Json | undefined {
  const ct = ref[CREDENTIAL_TYPE_KEY] as string;
  const id = typeof ref["@id"] === "string" ? (ref["@id"] as string) : "";
  const orgDid = id.split("#", 1)[0];
  if (orgDid in orgSources && ct in orgSources[orgDid]) {
    return orgSources[orgDid][ct];
  }
  return inputs[ct];
}

async function main(): Promise<void> {
  if (!existsSync(GAIAX_DIR)) {
    throw new Error(`gaiax examples directory not found: ${GAIAX_DIR}`);
  }
  const inputs = loadInputVcs();
  const orgSources = loadOrgInputVcs();
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
      const sourceVc = resolveReferent(ref, inputs, orgSources);
      if (!sourceVc) {
        fileErrors.push(
          `cannot resolve referent for credentialType '${credentialType}' / @id ${ref["@id"]}`,
        );
        continue;
      }
      // The digest must match its source-of-truth VC (the default input VC,
      // or the org's own input trio for orgs listed in ORG_INPUT_FILES).
      if (!(await verifyDigestSri(sourceVc, stored))) {
        fileErrors.push(
          `${credentialType} digestSRI does not match its source VC\n` +
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
