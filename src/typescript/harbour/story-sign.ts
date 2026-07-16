/**
 * Issue example credentials as dc+sd-jwt using the harbour TypeScript SDK.
 *
 * Mirror of the Python ``credentials.example_signer`` pipeline
 * (``docs/specs/batched-credential-evidence.md``): reads expanded examples from
 * ``examples/*.json`` and ``examples/gaiax/*.json`` and issues dc+sd-jwt
 * credentials with batched evidence into each directory's ``signed/`` folder.
 *
 *   - Issuers are sovereign (ADR-006): every proof is executed by the Signing
 *     Service key, with the proof ``kid`` resolved at signing time from the
 *     issuer's DID document (examples/did-ethr/) — the assertion method whose
 *     publicKeyJwk matches the Signing Service key. did:ethr fragments are
 *     per-update-event and never hardcoded.
 *   - Credentials carrying ``harbour:CredentialEvidenceBatch`` are grouped into a
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
  EVIDENCE_TYPE,
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

// Placeholder KB-JWT `sd_hash` for the simulated wallet ceremony (spec §4.3):
// every real KB-JWT carries an sd_hash (RFC 9901 §4.3), but the story pipeline
// has no actual OID4VP presentation to hash, so it uses this fixed value —
// SHA-256 of "harbour-credentials example ceremony: no real OID4VP
// presentation". Downstream verifiers ignore the value by spec. Mirrors
// EXAMPLE_SD_HASH in credentials/example_signer.py.
const EXAMPLE_SD_HASH = "s0c-KDj7V3cRdVS9sTSAoiOLY-kvvmMdIk1wO0yt974";

interface RoleKeyEntry {
  privateKey: CryptoKey;
  kid: string;
  /** Public JWK coordinates, for matching against DID-document methods. */
  publicJwk?: { x: string; y: string };
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
  roleDidKeys: Map<string, string>;
}

async function loadRoleKeyring(): Promise<RoleKeyring> {
  const mapping = JSON.parse(
    readFileSync(join(KEYS_DIR, "role-did-mapping.json"), "utf-8"),
  ) as Record<string, { did_ethr: string; did_key?: string }>;
  const byDID = new Map<string, RoleKeyEntry>();
  const roleDids = new Map<string, string>();
  const roleDidKeys = new Map<string, string>();
  for (const [role, filename] of Object.entries(ROLE_FILES)) {
    const jwk: JWK = JSON.parse(readFileSync(join(KEYS_DIR, filename), "utf-8"));
    const did = mapping[role]?.did_ethr;
    if (!did) continue;
    byDID.set(did, {
      privateKey: await importP256PrivateKey(jwk),
      kid: `${did}#controller`,
      publicJwk: { x: jwk.x as string, y: jwk.y as string },
    });
    roleDids.set(role, did);
    const didKey = mapping[role]?.did_key;
    if (didKey) roleDidKeys.set(role, didKey);
  }
  return { byDID, roleDids, roleDidKeys };
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
      // First colon only, KEEPING the remainder — JS split(":", 2) truncates
      // a local name containing a colon (Python mirror: split(":", 1)).
      const sep = t.indexOf(":");
      const prefix = t.slice(0, sep);
      const local = t.slice(sep + 1);
      const base = VCT_PREFIX[prefix];
      if (base) return base + local;
    }
  }
  return DEFAULT_VCT;
}

// Segment lists, not dot-strings — claim keys contain dots (harbour.gx:*).
function disclosablePaths(vc: Record<string, unknown>): string[][] {
  const cs = vc.credentialSubject;
  if (!cs || typeof cs !== "object") return [];
  return Object.keys(cs as object)
    .filter((k) => k !== "id" && k !== "type")
    .map((k) => ["credentialSubject", k]);
}

/** The harbour:CredentialEvidenceBatch object, if any (exact type match). */
function batchEvidenceEntry(
  vc: Record<string, unknown>,
): Record<string, unknown> | null {
  const evidence = vc.evidence;
  if (!Array.isArray(evidence) || evidence.length === 0) return null;
  const ev = evidence[0];
  if (!ev || typeof ev !== "object") return null;
  let types = (ev as Record<string, unknown>).type;
  if (typeof types === "string") types = [types];
  if (Array.isArray(types) && types.some((t) => t === EVIDENCE_TYPE)) {
    return ev as Record<string, unknown>;
  }
  return null;
}

function batchAuthorizer(vc: Record<string, unknown>): string | null {
  const ev = batchEvidenceEntry(vc);
  if (ev === null) return null;
  const authorizer = ev.authorizedBy;
  return typeof authorizer === "string" ? authorizer : null;
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

/** did -> [(vm id, jwk x/y)] for every P-256 assertion method in the example DID docs. */
type AssertionMethods = Map<string, { id: string; x: string; y: string }[]>;

/**
 * Read `examples/did-ethr/*.did.json` (standing in for live did:ethr
 * resolution) and index each document's P-256 assertion methods.
 */
function loadAssertionMethods(): AssertionMethods {
  const out: AssertionMethods = new Map();
  const dir = join(EXAMPLES_DIR, "did-ethr");
  let files: string[] = [];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".did.json")).sort();
  } catch {
    return out;
  }
  for (const f of files) {
    const doc = JSON.parse(readFileSync(join(dir, f), "utf-8")) as Record<
      string,
      unknown
    >;
    const did = doc.id;
    if (typeof did !== "string") continue;
    const assertion = new Set(
      Array.isArray(doc.assertionMethod) ? (doc.assertionMethod as string[]) : [],
    );
    const methods: { id: string; x: string; y: string }[] = [];
    for (const vm of Array.isArray(doc.verificationMethod)
      ? (doc.verificationMethod as Record<string, unknown>[])
      : []) {
      const id = vm.id;
      const jwk = vm.publicKeyJwk as Record<string, unknown> | undefined;
      if (
        typeof id === "string" &&
        assertion.has(id) &&
        jwk &&
        jwk.crv === "P-256" &&
        typeof jwk.x === "string" &&
        typeof jwk.y === "string"
      ) {
        methods.push({ id, x: jwk.x, y: jwk.y });
      }
    }
    out.set(did, methods);
  }
  return out;
}

/**
 * Signing Service key + kid for a credential proof (ADR-006).
 *
 * The Signing Service executes every proof; the kid is RESOLVED AT SIGNING
 * TIME from the issuer's DID document — the assertion method whose
 * publicKeyJwk matches the Signing Service key. did:ethr fragments are
 * per-update-event and can never be hardcoded.
 */
function proofKey(
  issuerDid: string,
  keyring: RoleKeyring,
  fallback: RoleKeyEntry,
  assertionMethods: AssertionMethods,
): RoleKeyEntry {
  const ssDid = keyring.roleDids.get("haven");
  const ss = ssDid ? keyring.byDID.get(ssDid) : undefined;
  if (ssDid && ss && ss.publicJwk) {
    for (const vm of assertionMethods.get(issuerDid) ?? []) {
      if (vm.x === ss.publicJwk.x && vm.y === ss.publicJwk.y) {
        return { privateKey: ss.privateKey, kid: vm.id };
      }
    }
    throw new Error(
      `issuer ${issuerDid} publishes no assertion method for the Signing ` +
        "Service key in its DID document (ADR-006 mandate missing) — cannot sign",
    );
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
  assertionMethods: AssertionMethods,
): Promise<void> {
  const proof = proofKey(
    (item.vc.issuer as string) ?? "",
    keyring,
    fallback,
    assertionMethods,
  );
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
  assertionMethods: AssertionMethods,
): Promise<void> {
  // The admin wallet key stands in via the org's controller key (ADR-006 §3).
  const walletKey = resolveKey(authorizer, keyring.byDID, fallback);
  // All credentials in a batch share an issuer: for the identity credentials
  // authorizedBy MUST equal issuer (spec §6, step 6), and batches are grouped
  // by authorizer. Proofs are executed by the Signing Service via the
  // issuer's mandate key. The authorization KB-JWT is addressed (`aud`) to
  // the OID4VP intake verifier — the gatehouse acting for the Signing
  // Service, identified by its did:key (spec §4.3, §9.6).
  const issuerDid = (batch[0].vc.issuer as string) ?? "";
  const proof = proofKey(issuerDid, keyring, fallback, assertionMethods);
  const audience = keyring.roleDidKeys.get("haven") ?? fallback.kid;

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

  // 2. One wallet signature over the authorization message committing to the
  //    batch Merkle root; per-credential proof.
  const evidenceObjs = await buildBatchEvidence(payloads, walletKey.privateKey, {
    authorizedBy: authorizer,
    audience,
    sdHash: EXAMPLE_SD_HASH,
    domain: "harbour.local",
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
  const assertionMethods = loadAssertionMethods();

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
    await processBatch(batch, authorizer, keyring, fallback, assertionMethods);
    for (const b of batch) outputDirs.add(b.outputDir);
  }
  for (const item of plain) {
    await processPlain(item, keyring, fallback, assertionMethods);
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
