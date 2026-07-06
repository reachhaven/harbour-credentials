/**
 * Issue example credentials as dc+sd-jwt using the harbour TypeScript SDK.
 *
 * Mirror of the Python ``credentials.example_signer`` pipeline
 * (``docs/specs/batched-credential-evidence.md``): reads expanded examples from
 * ``examples/*.json`` and ``examples/gaiax/*.json`` and issues dc+sd-jwt
 * credentials with batched evidence into each directory's ``signed/`` folder.
 *
 *   - Issuers are sovereign (ADR-006): every proof is executed by the Signing
 *     Service key — as itself (#controller) on its own artifacts, and via the
 *     assertion-only #delegate-1 mandate in the issuer's DID document for
 *     sovereign issuers. The proof ``kid`` names that verification method.
 *   - Credentials carrying ``harbour:BatchCredentialEvidence`` are grouped into a
 *     batch per (output dir, authorizer). The authorizer's admin key signs ONE
 *     authorization JWT over the batch Merkle root; each credential gets its own
 *     inclusion proof. Salts are fixed first (buildSdJwtPayload), the root is
 *     signed, the full evidence is injected, then the issuer JWT is signed
 *     (signSdJwt).
 *   - Credentials with no/other evidence are issued as plain dc+sd-jwt.
 *
 * Output per credential: ``<name>.sd-jwt`` and ``<name>.decoded.json``.
 * Source examples are NEVER modified.
 */

import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  readdirSync,
  existsSync,
  unlinkSync,
  statSync,
} from "node:fs";
import { join, basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  importP256PrivateKey,
  importP256PublicKey,
  buildSdJwtPayload,
  signSdJwt,
  buildBatchEvidence,
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
const EXAMPLES_DIR = join(REPO_ROOT, "examples");

const VCT_PREFIX: Record<string, string> = {
  harbour: "https://w3id.org/reachhaven/harbour/core/v1/",
  "harbour.gx": "https://w3id.org/reachhaven/harbour/gx/v1/",
  "harbour.delegate": "https://w3id.org/reachhaven/harbour/delegate/v1/",
};
const DEFAULT_VCT = "https://w3id.org/reachhaven/harbour/core/v1/VerifiableCredential";

interface RoleKeyEntry {
  privateKey: CryptoKey;
  kid: string;
}

const ROLE_FILES: Record<string, string> = {
  "trust-anchor": "trust-anchor.p256.json",
  haven: "haven.p256.json",
  company: "company.p256.json",
  employee: "employee.p256.json",
  ascs: "ascs.p256.json",
};

interface RoleKeyring {
  byDID: Map<string, RoleKeyEntry>;
  roleDids: Map<string, string>;
}

async function loadRoleKeyring(): Promise<RoleKeyring> {
  const mapping = JSON.parse(
    readFileSync(join(KEYS_DIR, "role-did-mapping.json"), "utf-8"),
  ) as Record<string, { did_ethr: string }>;
  const byDID = new Map<string, RoleKeyEntry>();
  const roleDids = new Map<string, string>();
  for (const [role, filename] of Object.entries(ROLE_FILES)) {
    const jwk: JWK = JSON.parse(readFileSync(join(KEYS_DIR, filename), "utf-8"));
    const did = mapping[role]?.did_ethr;
    if (!did) continue;
    byDID.set(did, {
      privateKey: await importP256PrivateKey(jwk),
      kid: `${did}#controller`,
    });
    roleDids.set(role, did);
  }
  return { byDID, roleDids };
}

async function loadFallbackKey(): Promise<RoleKeyEntry> {
  const jwk: JWK = JSON.parse(
    readFileSync(join(KEYS_DIR, "test-keypair-p256.json"), "utf-8"),
  );
  await importP256PublicKey(jwk); // validate
  return {
    privateKey: await importP256PrivateKey(jwk),
    kid: "did:key:fallback#controller",
  };
}

// --- helpers ----------------------------------------------------------------

function vctForCredential(vc: Record<string, unknown>): string {
  for (const t of (vc.type as string[]) ?? []) {
    if (typeof t === "string" && t.includes(":")) {
      const [prefix, local] = t.split(":", 2);
      const base = VCT_PREFIX[prefix];
      if (base) return base + local;
    }
  }
  return DEFAULT_VCT;
}

function disclosablePaths(vc: Record<string, unknown>): string[] {
  const cs = vc.credentialSubject;
  if (!cs || typeof cs !== "object") return [];
  return Object.keys(cs as object)
    .filter((k) => k !== "id" && k !== "type")
    .map((k) => `credentialSubject.${k}`);
}

function batchAuthorizer(vc: Record<string, unknown>): string | null {
  const evidence = vc.evidence;
  if (!Array.isArray(evidence) || evidence.length === 0) return null;
  const ev = evidence[0];
  if (!ev || typeof ev !== "object") return null;
  let types = (ev as Record<string, unknown>).type;
  if (typeof types === "string") types = [types];
  if (
    Array.isArray(types) &&
    types.some((t) => typeof t === "string" && t.endsWith("BatchCredentialEvidence"))
  ) {
    const authorizer = (ev as Record<string, unknown>).authorizer;
    return typeof authorizer === "string" ? authorizer : null;
  }
  return null;
}

function b64urlToString(s: string): string {
  return Buffer.from(s, "base64url").toString("utf-8");
}

function decodeSdJwt(sdJwt: string): Record<string, unknown> {
  const parts = sdJwt.split("~");
  const [headerB64, payloadB64] = parts[0].split(".");
  return {
    header: JSON.parse(b64urlToString(headerB64)),
    payload: JSON.parse(b64urlToString(payloadB64)),
    disclosures: parts
      .slice(1)
      .filter((p) => p.length > 0)
      .map((p) => JSON.parse(b64urlToString(p))),
  };
}

function writeOutputs(outputDir: string, stem: string, sdJwt: string): void {
  mkdirSync(outputDir, { recursive: true });
  writeFileSync(join(outputDir, `${stem}.sd-jwt`), sdJwt + "\n");
  writeFileSync(
    join(outputDir, `${stem}.decoded.json`),
    JSON.stringify(
      { _description: `Decoded dc+sd-jwt for ${stem}`, ...decodeSdJwt(sdJwt) },
      null,
      2,
    ) + "\n",
  );
}

function resolveKey(
  did: string,
  byDID: Map<string, RoleKeyEntry>,
  fallback: RoleKeyEntry,
): RoleKeyEntry {
  return byDID.get(did) ?? fallback;
}

/**
 * Signing Service key + kid for a credential proof (ADR-006).
 *
 * The Signing Service executes every proof: as itself (#controller) on its
 * own artifacts, and through the assertion-only #delegate-1 mandate in the
 * issuer's DID document for sovereign issuers.
 */
function proofKey(
  issuerDid: string,
  keyring: RoleKeyring,
  fallback: RoleKeyEntry,
): RoleKeyEntry {
  const ssDid = keyring.roleDids.get("haven");
  const ss = ssDid ? keyring.byDID.get(ssDid) : undefined;
  if (ssDid && ss) {
    const fragment = issuerDid === ssDid ? "#controller" : "#delegate-1";
    return { privateKey: ss.privateKey, kid: `${issuerDid}${fragment}` };
  }
  return fallback;
}

interface BatchItem {
  path: string;
  vc: Record<string, unknown>;
  outputDir: string;
}

async function processPlain(
  item: BatchItem,
  keyring: RoleKeyring,
  fallback: RoleKeyEntry,
): Promise<void> {
  const proof = proofKey((item.vc.issuer as string) ?? "", keyring, fallback);
  const { payload, disclosures } = buildSdJwtPayload(item.vc, {
    vct: vctForCredential(item.vc),
    disclosable: disclosablePaths(item.vc),
  });
  const sdJwt = await signSdJwt(payload, disclosures, proof.privateKey, {
    kid: proof.kid,
  });
  writeOutputs(item.outputDir, basename(item.path, ".json"), sdJwt);
}

async function processBatch(
  batch: BatchItem[],
  authorizer: string,
  keyring: RoleKeyring,
  fallback: RoleKeyEntry,
): Promise<void> {
  const authorizerKey = resolveKey(authorizer, keyring.byDID, fallback);
  // All credentials in a batch share an issuer (usually the authorizer org
  // itself, ADR-006); proofs are executed by the Signing Service via the
  // issuer's mandate key.
  const issuerDid = (batch[0].vc.issuer as string) ?? "";
  const proof = proofKey(issuerDid, keyring, fallback);

  // 1. Fix salts.
  const payloads: Record<string, unknown>[] = [];
  const disclosures: string[][] = [];
  for (const item of batch) {
    const built = buildSdJwtPayload(item.vc, {
      vct: vctForCredential(item.vc),
      disclosable: disclosablePaths(item.vc),
    });
    payloads.push(built.payload);
    disclosures.push(built.disclosures);
  }

  // 2. One signature over the batch Merkle root; per-credential proof.
  const evidenceObjs = await buildBatchEvidence(payloads, authorizerKey.privateKey, {
    authorizerDid: authorizer,
    audience: issuerDid,
    kid: authorizerKey.kid,
  });

  // 3. Inject the full evidence and sign each issuer JWT.
  for (let i = 0; i < batch.length; i++) {
    payloads[i].evidence = [evidenceObjs[i]];
    const sdJwt = await signSdJwt(payloads[i], disclosures[i], proof.privateKey, {
      kid: proof.kid,
    });
    writeOutputs(batch[i].outputDir, basename(batch[i].path, ".json"), sdJwt);
  }
}

function discoverExamples(dir: string): string[] {
  const keywords = ["credential", "receipt", "offering"];
  try {
    return readdirSync(dir)
      .filter((f) => f.endsWith(".json") && keywords.some((kw) => f.includes(kw)))
      .sort()
      .map((f) => join(dir, f));
  } catch {
    return [];
  }
}

async function main(): Promise<void> {
  const keyring = await loadRoleKeyring();
  const fallback = await loadFallbackKey();

  console.log(`  Loaded ${keyring.byDID.size} role keys`);

  const examples = [
    ...discoverExamples(EXAMPLES_DIR),
    ...discoverExamples(join(EXAMPLES_DIR, "gaiax")),
  ];
  if (examples.length === 0) {
    console.error("No example credentials found");
    process.exit(1);
  }

  // Clear stale artifacts (signed/ is gitignored, regenerated each run).
  const signedDirs = new Set(examples.map((p) => join(dirname(p), "signed")));
  for (const d of signedDirs) {
    if (existsSync(d)) {
      for (const f of readdirSync(d)) {
        const fp = join(d, f);
        if (statSync(fp).isFile()) unlinkSync(fp);
      }
    }
  }

  console.log(`Issuing ${examples.length} example credentials (dc+sd-jwt)...`);

  // Partition into batches (by output dir + authorizer) and plain credentials.
  const batches = new Map<string, BatchItem[]>();
  const plain: BatchItem[] = [];
  for (const path of examples) {
    const vc = JSON.parse(readFileSync(path, "utf-8")) as Record<string, unknown>;
    const outputDir = join(dirname(path), "signed");
    const authorizer = batchAuthorizer(vc);
    const item: BatchItem = { path, vc, outputDir };
    if (authorizer) {
      const key = `${outputDir} ${authorizer}`;
      (batches.get(key) ?? batches.set(key, []).get(key)!).push(item);
    } else {
      plain.push(item);
    }
  }

  const outputDirs = new Set<string>();
  for (const [key, batch] of batches) {
    const authorizer = key.split(" ")[1];
    const members = batch.map((b) => basename(b.path)).join(", ");
    console.log(`  batch (authorizer ${authorizer.slice(-8)}, N=${batch.length}): ${members}`);
    await processBatch(batch, authorizer, keyring, fallback);
    for (const b of batch) outputDirs.add(b.outputDir);
  }
  for (const item of plain) {
    await processPlain(item, keyring, fallback);
    outputDirs.add(item.outputDir);
    console.log(`  plain: ${basename(item.path)}`);
  }

  for (const outDir of [...outputDirs].sort()) {
    console.log(`\nGenerated ${readdirSync(outDir).length} files in ${outDir}/`);
  }
  console.log("Done.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
