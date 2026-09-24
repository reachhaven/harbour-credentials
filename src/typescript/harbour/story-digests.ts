/**
 * Verify the `digestSRI` integrity hashes in the Gaia-X examples (TypeScript).
 *
 * Mirrors the Python `credentials.digest_sri_examples --check` step: each
 * `harbour.gx:CompliantCredentialReference` in the example credentials must
 * carry a `harbour.gx:digestSRI` that matches the source-of-truth input VC
 * (and its inline `harbour.gx:embeddedCredential`, when present), recomputed
 * with the real `verifyDigestSri` function.
 *
 * Run via `yarn story:digests` (invoked by `just story-ts`).
 */

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyDigestSri, computeDigestSri, canonicalJson } from "./index.js";

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
  "gx:NaturalPerson": "gx-natural-person.json",
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

/** Yield every object found anywhere in `node`. */
function iterDicts(node: unknown, out: Json[]): void {
  if (Array.isArray(node)) {
    for (const item of node) iterDicts(item, out);
  } else if (node !== null && typeof node === "object") {
    const obj = node as Json;
    out.push(obj);
    for (const value of Object.values(obj)) iterDicts(value, out);
  }
}

function hasType(node: Json, typeValue: string): boolean {
  const t = node["type"];
  const types = typeof t === "string" ? [t] : Array.isArray(t) ? t : [];
  return types.includes(typeValue);
}

/** The org DID if `cred` is a self-signed LegalPersonCredential, else undefined. */
function selfSignedOrg(cred: Json): string | undefined {
  if (!hasType(cred, "harbour.gx:LegalPersonCredential")) return undefined;
  const subject = cred["credentialSubject"];
  if (subject === null || typeof subject !== "object") return undefined;
  const orgDid = (subject as Json)["id"];
  if (typeof orgDid !== "string" || !orgDid || cred["issuer"] !== orgDid) return undefined;
  return orgDid;
}

/**
 * Map a self-signed org DID -> { credentialType: its own bundled gx VC }.
 *
 * Mirrors `credentials.digest_sri_examples.load_self_signed_sources`: a
 * self-signed `harbour.gx:LegalPersonCredential` (issuer == credentialSubject.id,
 * e.g. the Trust Anchor) bundles its own gx VCs in its evidence VP, and those are
 * that org's source of truth (it has no Example-Corp input file).
 *
 * The credential's canonical copy is the file that has it at its root
 * (`trust-anchor-credential.json`). Every copy embedded in another credential's
 * evidence VP must equal it, and the bundle may hold one VC per credentialType;
 * otherwise the digests would depend on whichever copy is read first.
 *
 * Throws when a self-signed credential has no `id`, is not the root of exactly
 * one file, has a drifted embedded copy, or bundles two VCs of one type.
 */
function loadSelfSignedSources(files: string[]): Record<string, Record<string, Json>> {
  const copies = new Map<string, { path: string; isRoot: boolean; cred: Json }[]>();
  for (const path of files) {
    const obj = JSON.parse(readFileSync(path, "utf-8")) as Json;
    const dicts: Json[] = [];
    iterDicts(obj, dicts);
    for (const cred of dicts) {
      const orgDid = selfSignedOrg(cred);
      if (orgDid === undefined) continue;
      const credId = cred["id"];
      if (typeof credId !== "string" || !credId) {
        throw new Error(`${basename(path)}: self-signed credential of ${orgDid} has no id`);
      }
      if (!copies.has(credId)) copies.set(credId, []);
      copies.get(credId)!.push({ path, isRoot: cred === obj, cred });
    }
  }

  const sources: Record<string, Record<string, Json>> = {};
  for (const [credId, found] of copies) {
    const roots = found.filter((c) => c.isRoot);
    if (roots.length !== 1) {
      const where = roots.map((c) => basename(c.path)).sort().join(", ") || "no file";
      throw new Error(
        `self-signed credential ${credId} must be the root of exactly one file ` +
          `(its canonical copy); found: ${where}`,
      );
    }
    const canonical = roots[0];
    const canonicalText = canonicalJson(canonical.cred);
    const drifted = [
      ...new Set(
        found
          .filter((c) => !c.isRoot && canonicalJson(c.cred) !== canonicalText)
          .map((c) => basename(c.path)),
      ),
    ].sort();
    if (drifted.length > 0) {
      throw new Error(
        `self-signed credential ${credId}: the copy embedded in ` +
          `${drifted.join(", ")} differs from ${basename(canonical.path)}`,
      );
    }

    const orgDid = selfSignedOrg(canonical.cred) as string;
    const bundle = (sources[orgDid] ??= {});
    const inners: Json[] = [];
    iterDicts(canonical.cred["evidence"] ?? [], inners);
    for (const inner of inners) {
      const cs = inner["credentialSubject"];
      if (cs === null || typeof cs !== "object") continue;
      const credentialType = (cs as Json)["type"];
      if (typeof credentialType !== "string" || !(credentialType in INPUT_FILES)) continue;
      if (credentialType in bundle) {
        throw new Error(
          `self-signed organization ${orgDid} bundles more than one ` +
            `${credentialType} VC (${basename(canonical.path)})`,
        );
      }
      bundle[credentialType] = inner;
    }
  }
  return sources;
}

/**
 * The gx VC a reference's digestSRI is taken over. A reference whose `@id` names
 * a self-signed org resolves ONLY against that org's own bundle; it never falls
 * back to the Example-Corp input VC, which describes a different organization.
 * Any other reference resolves to the input VC for its credentialType.
 *
 * Throws when there is no source VC for the reference.
 */
function resolveReferent(
  ref: Json,
  inputs: Record<string, Json>,
  selfSigned: Record<string, Record<string, Json>>,
): Json {
  const credentialType = ref[CREDENTIAL_TYPE_KEY] as string;
  const id = typeof ref["@id"] === "string" ? (ref["@id"] as string) : "";
  const orgDid = id.split("#", 1)[0];
  if (orgDid in selfSigned) {
    const bundle = selfSigned[orgDid];
    if (!(credentialType in bundle)) {
      const bundled = Object.keys(bundle).sort().join(", ") || "none";
      throw new Error(
        `self-signed organization ${orgDid} bundles no '${credentialType}' VC in ` +
          `its evidence (bundled: ${bundled})`,
      );
    }
    return bundle[credentialType];
  }
  if (!(credentialType in inputs)) {
    throw new Error(
      `no source-of-truth input VC for credentialType '${credentialType}' (@id ${ref["@id"]})`,
    );
  }
  return inputs[credentialType];
}

async function main(): Promise<void> {
  if (!existsSync(GAIAX_DIR)) {
    throw new Error(`gaiax examples directory not found: ${GAIAX_DIR}`);
  }
  const inputs = loadInputVcs();
  let selfSigned: Record<string, Record<string, Json>> = {};
  try {
    selfSigned = loadSelfSignedSources(targetFiles());
  } catch (e) {
    console.error(`\nFAIL: ${(e as Error).message}`);
    process.exit(1);
  }
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
      let sourceVc: Json;
      try {
        sourceVc = resolveReferent(ref, inputs, selfSigned);
      } catch (e) {
        fileErrors.push((e as Error).message);
        continue;
      }
      // The digest must match its source-of-truth VC (Example-Corp input VC,
      // or the org's own bundled gx VC for self-signed organizations).
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
