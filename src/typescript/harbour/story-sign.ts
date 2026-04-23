/**
 * Sign example credentials using the harbour TypeScript SDK.
 *
 * Mirrors the Python ``credentials.example_signer`` pipeline: reads expanded
 * examples from ``examples/*.json`` and ``examples/gaiax/*.json``, signs them
 * using per-role P-256 keys, and writes signed artifacts to ``examples/signed/``
 * and ``examples/gaiax/signed/``.
 *
 * Each role in the trust chain uses a **separate P-256 key** so that the
 * signed artifacts cryptographically demonstrate who signed what:
 *
 *   - Trust Anchor key  → self-signed VC, evidence VPs authorising orgs
 *   - Haven key         → all outer credentials (issuer)
 *   - Company key       → evidence VPs authorising employees
 *   - Employee key      → consent VPs for delegated signing
 *
 * Output per credential:
 *   - <name>.jwt                      — VC-JOSE-COSE compact JWS (wire format)
 *   - <name>.decoded.json             — Decoded JWT header + payload
 *   - <name>.evidence-vp.jwt          — Evidence VP JWT (if evidence present)
 *   - <name>.evidence-vp.decoded.json — Decoded evidence VP with inner VCs decoded
 *
 * Source examples are NEVER modified.
 */

import { readFileSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { join, basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  importP256PrivateKey,
  importP256PublicKey,
  p256PublicKeyToDidKey,
  signVcJose,
  signVpJose,
  type JWK,
} from "./index.js";

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function findRepoRoot(): string {
  let current = resolve(__dirname);
  while (current !== dirname(current)) {
    // Look for the harbour-credentials repo specifically (has tests/fixtures/keys)
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
const KEYS_DIR = join(REPO_ROOT, "tests", "fixtures", "keys");
const EXAMPLES_DIR = join(REPO_ROOT, "examples");

// ---------------------------------------------------------------------------
// Role keyring
// ---------------------------------------------------------------------------

interface RoleDIDMapping {
  [role: string]: {
    did_ethr: string;
    did_key: string;
    eth_addr: string;
  };
}

interface RoleKeyEntry {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  kid: string;
}

const ROLE_FILES: Record<string, string> = {
  "trust-anchor": "trust-anchor.p256.json",
  haven: "haven.p256.json",
  company: "company.p256.json",
  employee: "employee.p256.json",
  ascs: "ascs.p256.json",
};

async function loadRoleKeyring(): Promise<{
  byDID: Map<string, RoleKeyEntry>;
  byRole: Map<string, RoleKeyEntry>;
}> {
  const mapping: RoleDIDMapping = JSON.parse(
    readFileSync(join(KEYS_DIR, "role-did-mapping.json"), "utf-8"),
  );

  const byDID = new Map<string, RoleKeyEntry>();
  const byRole = new Map<string, RoleKeyEntry>();

  for (const [role, filename] of Object.entries(ROLE_FILES)) {
    const jwk: JWK = JSON.parse(
      readFileSync(join(KEYS_DIR, filename), "utf-8"),
    );
    const privateKey = await importP256PrivateKey(jwk);
    const publicKey = await importP256PublicKey(jwk);
    const did = mapping[role]?.did_ethr;
    if (!did) continue;

    const kid = `${did}#controller`;
    const entry: RoleKeyEntry = { privateKey, publicKey, kid };
    byDID.set(did, entry);
    byRole.set(role, entry);
  }

  return { byDID, byRole };
}

async function loadFallbackKey(): Promise<{
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  kid: string;
}> {
  const jwk: JWK = JSON.parse(
    readFileSync(join(KEYS_DIR, "test-keypair-p256.json"), "utf-8"),
  );
  const privateKey = await importP256PrivateKey(jwk);
  const publicKey = await importP256PublicKey(jwk);
  const didKey = await p256PublicKeyToDidKey(publicKey);
  const kid = `${didKey}#${didKey.split(":").pop()}`;
  return { privateKey, publicKey, kid };
}

// ---------------------------------------------------------------------------
// JWT decode (no verification — for decoded companion files)
// ---------------------------------------------------------------------------

function b64urlDecode(s: string): string {
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(padded, "base64url").toString("utf-8");
}

function decodeJwt(token: string): { header: unknown; payload: unknown } {
  const [headerB64, payloadB64] = token.split(".");
  return {
    header: JSON.parse(b64urlDecode(headerB64)),
    payload: JSON.parse(b64urlDecode(payloadB64)),
  };
}

// ---------------------------------------------------------------------------
// Evidence VP signing (matches Python sign_evidence_vp)
// ---------------------------------------------------------------------------

async function signEvidenceVp(
  vp: Record<string, unknown>,
  holderKey: CryptoKey,
  holderKid: string,
  byDID: Map<string, RoleKeyEntry>,
  fallbackKey: CryptoKey,
  fallbackKid: string,
): Promise<string> {
  const cleanVp: Record<string, unknown> = {
    "@context": vp["@context"] ?? ["https://www.w3.org/ns/credentials/v2"],
    type: vp["type"] ?? ["VerifiablePresentation"],
  };
  if (vp["holder"]) cleanVp["holder"] = vp["holder"];

  const innerVcs = (vp["verifiableCredential"] as unknown[]) ?? [];
  const innerJwts: string[] = [];

  for (const vc of innerVcs) {
    if (typeof vc === "object" && vc !== null) {
      const vcObj = vc as Record<string, unknown>;
      const innerIssuer = (vcObj["issuer"] as string) ?? "";
      const resolved = byDID.get(innerIssuer);
      const innerKey = resolved?.privateKey ?? fallbackKey;
      const innerKid = resolved?.kid ?? fallbackKid;
      const jwt = await signVcJose(vcObj, innerKey, { kid: innerKid });
      innerJwts.push(jwt);
    } else if (typeof vc === "string") {
      innerJwts.push(vc);
    }
  }
  if (innerJwts.length > 0) {
    cleanVp["verifiableCredential"] = innerJwts;
  }

  const nonce = vp["nonce"] as string | undefined;
  return signVpJose(cleanVp, holderKey, { kid: holderKid, nonce });
}

// ---------------------------------------------------------------------------
// Decode evidence VP with inner VCs decoded inline
// ---------------------------------------------------------------------------

function decodeEvidenceVp(
  vpJwt: string,
): Record<string, unknown> {
  const decoded = decodeJwt(vpJwt) as {
    header: unknown;
    payload: Record<string, unknown>;
  };
  const inners = (decoded.payload["verifiableCredential"] as unknown[]) ?? [];
  const decodedInners: unknown[] = [];

  for (const inner of inners) {
    if (typeof inner === "string" && inner.includes(".")) {
      const innerDecoded = decodeJwt(inner);
      decodedInners.push({ _jwt: inner, _decoded: innerDecoded });
    } else {
      decodedInners.push(inner);
    }
  }
  if (decodedInners.length > 0) {
    decoded.payload["verifiableCredential"] = decodedInners;
  }

  return decoded as unknown as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Process a single example credential
// ---------------------------------------------------------------------------

async function processExample(
  examplePath: string,
  fallbackPrivateKey: CryptoKey,
  fallbackKid: string,
  outputDir: string,
  byDID: Map<string, RoleKeyEntry>,
): Promise<string> {
  const vc: Record<string, unknown> = JSON.parse(
    readFileSync(examplePath, "utf-8"),
  );
  const stem = basename(examplePath, ".json");

  // Determine outer credential signing key
  const issuerDid = (vc["issuer"] as string) ?? "";
  const outerResolved = byDID.get(issuerDid);
  const outerKey = outerResolved?.privateKey ?? fallbackPrivateKey;
  const outerKid = outerResolved?.kid ?? fallbackKid;

  // Deep-copy for signing (don't mutate source)
  const vcForSigning: Record<string, unknown> = JSON.parse(JSON.stringify(vc));

  let evidenceVpJwt: string | null = null;

  // Sign evidence VPs if present
  const evidence = vcForSigning["evidence"] as
    | Record<string, unknown>[]
    | undefined;
  if (evidence) {
    for (const ev of evidence) {
      const vpObj = ev["verifiablePresentation"];
      if (typeof vpObj === "object" && vpObj !== null) {
        const vp = vpObj as Record<string, unknown>;
        const evHolder = (vp["holder"] as string) ?? "";
        const holderResolved = byDID.get(evHolder);
        const evKey = holderResolved?.privateKey ?? fallbackPrivateKey;
        const evKid = holderResolved?.kid ?? fallbackKid;
        evidenceVpJwt = await signEvidenceVp(
          vp,
          evKey,
          evKid,
          byDID,
          fallbackPrivateKey,
          fallbackKid,
        );
        ev["verifiablePresentation"] = evidenceVpJwt;
      }
    }
  }

  // Sign the outer credential
  const vcJwt = await signVcJose(vcForSigning, outerKey, { kid: outerKid });

  // Write outputs
  mkdirSync(outputDir, { recursive: true });

  // 1. Outer VC JWT
  const jwtPath = join(outputDir, `${stem}.jwt`);
  writeFileSync(jwtPath, vcJwt + "\n");

  // 2. Decoded outer JWT
  const decoded = decodeJwt(vcJwt);
  const decodedPath = join(outputDir, `${stem}.decoded.json`);
  writeFileSync(
    decodedPath,
    JSON.stringify(
      { _description: `Decoded VC-JOSE-COSE JWT for ${stem}`, ...decoded },
      null,
      2,
    ) + "\n",
  );

  // 3. Evidence VP JWT (if applicable)
  if (evidenceVpJwt) {
    const evJwtPath = join(outputDir, `${stem}.evidence-vp.jwt`);
    writeFileSync(evJwtPath, evidenceVpJwt + "\n");

    // 4. Decoded evidence VP
    const evDecoded = decodeEvidenceVp(evidenceVpJwt);
    const evDecodedPath = join(outputDir, `${stem}.evidence-vp.decoded.json`);
    writeFileSync(
      evDecodedPath,
      JSON.stringify(
        {
          _description: `Decoded evidence VP JWT for ${stem}`,
          ...evDecoded,
        },
        null,
        2,
      ) + "\n",
    );
  }

  return jwtPath;
}

// ---------------------------------------------------------------------------
// Example discovery (matches Python filter)
// ---------------------------------------------------------------------------

function discoverExamples(dir: string): string[] {
  const keywords = ["credential", "receipt", "offering"];
  try {
    return readdirSync(dir)
      .filter(
        (f) =>
          f.endsWith(".json") &&
          keywords.some((kw) => f.includes(kw)),
      )
      .sort()
      .map((f) => join(dir, f));
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const { byDID, byRole } = await loadRoleKeyring();
  const fallback = await loadFallbackKey();

  console.log(`  Loaded ${byDID.size} role keys:`);
  for (const [role, entry] of byRole) {
    console.log(`    ${role}: ${entry.kid.split("#")[0]}`);
  }

  // Issuer → kid mapping (for display, matching Python output)
  const issuerKids = new Map<string, string>();
  for (const [did, entry] of byDID) {
    issuerKids.set(did, entry.kid);
  }
  console.log("  Issuer -> kid mapping:");
  for (const [did, kid] of issuerKids) {
    console.log(`    ${did} -> ${kid}`);
  }

  // Discover examples
  const examples = [
    ...discoverExamples(EXAMPLES_DIR),
    ...discoverExamples(join(EXAMPLES_DIR, "gaiax")),
  ];

  if (examples.length === 0) {
    console.error("No example credentials found");
    process.exit(1);
  }

  console.log(
    `Signing ${examples.length} example credentials with test P-256 keys...`,
  );

  const outputDirs = new Set<string>();
  for (const examplePath of examples) {
    const outputDir = join(dirname(examplePath), "signed");
    const jwtPath = await processExample(
      examplePath,
      fallback.privateKey,
      fallback.kid,
      outputDir,
      byDID,
    );
    outputDirs.add(outputDir);

    const parentName = basename(dirname(examplePath));
    const prefix = parentName !== "examples" ? `${parentName}/` : "";
    console.log(
      `  ${prefix}${basename(examplePath)} -> signed/${basename(jwtPath)}`,
    );
  }

  // List generated files
  for (const outDir of [...outputDirs].sort()) {
    const files = readdirSync(outDir).sort();
    console.log(`\nGenerated ${files.length} files in ${outDir}/`);
    for (const f of files) {
      console.log(`  ${f}`);
    }
  }

  console.log("Done.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
