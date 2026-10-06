/**
 * Passkey evidence: verify who approved a credential, up to the trust anchor.
 *
 * Mirrors the Python `harbour.evidence` module and implements
 * `docs/specs/passkey-evidence.md`. Every member and organisation credential
 * carries one `HavenWebAuthnEvidence` object: a WebAuthn assertion by the
 * approver's passkey over the payload digest, or, for a batch approved with a
 * single tap, over the Merkle root of the batch (`merklePath`, see `merkle.ts`).
 *
 * A trust anchor admin approves with a passkey taken from the trust anchor
 * key log (§4.5) as of the payload's `iat`, never from the trust anchor DID
 * document: the log is replayed once per verification and a broken log fails
 * it (`key-log-invalid`, `key-log-unavailable`).
 *
 * Both runtimes run the same checks in the same order and report the same
 * failure reasons. DID and key log resolution are injected.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import canonicalize from "canonicalize";
import { compactVerify, decodeProtectedHeader, importJWK } from "jose";
import {
  b64urlDecode,
  b64urlEncode,
  foldPath,
  MerklePathError,
  payloadDigestBytes,
  type MerklePathElement,
} from "./merkle.js";

export const CREDENTIAL_JWT_TYP = "dc+sd-jwt";
export const EVIDENCE_TYPE = "HavenWebAuthnEvidence";
export const RELYING_PARTY_SERVICE_TYPE = "HavenWebAuthnRelyingParty";
export const KEY_LOG_SERVICE_TYPE = "HavenTrustAnchorKeyLog";
export const INSTRUCTION_CONTEXT = "https://schema.reachhaven.com/instructions/v1";
export const DEFAULT_MAX_EVIDENCE_DEPTH = 8;

/** Credentials held by a person that carry memberOf, role and authenticators. */
export const MEMBER_VCTS: readonly string[] = [
  "haven:MemberCredential",
  "simpulseid:UserCredential",
  "simpulseid:AdministratorCredential",
];
/** Organisation-level credentials: issued by the trust anchor, published. */
export const ORGANISATION_VCTS: readonly string[] = [
  "haven:OrganisationCredential",
  "simpulseid:ParticipantCredential",
  "simpulseid:AscsBaseMembershipCredential",
  "simpulseid:AscsEnvitedMembershipCredential",
];

const INSTRUCTION_TYPES = ["haven:RevokeCredential"];
const CLOCK_SKEW_SECONDS = 60;
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const SUPPORTED_JWS_ALGS = new Set(["ES256", "EdDSA", "Ed25519"]);
const B64URL_NONEMPTY = /^[A-Za-z0-9_-]+$/;
const URN_UUID =
  /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CRSET_ENTRY_ID = /^0x[0-9a-f]{64}$/;
const KEY_LOG_KINDS = ["credential", "revocation", "passkey_revoked"];

// --- types ------------------------------------------------------------------

export type Jwk = Record<string, unknown> & { kty?: unknown; crv?: unknown };
export type DidDocument = Record<string, unknown> & { id?: unknown };
/** Resolves a DID to its document; must reject when it cannot be resolved. */
export type ResolveDid = (did: string) => Promise<DidDocument>;
/** Fetches the key log entries of a trust anchor; must reject when it cannot. */
export type ResolveKeyLog = (trustAnchorDid: string) => Promise<unknown>;

/** One trust anchor key log entry (spec §4.5). */
export interface TrustAnchorKeyLogEntry {
  seq: number;
  kind: "credential" | "revocation" | "passkey_revoked";
  at: number;
  prev: string | null;
  hash: string;
  material:
    | { kind: "credential"; jwt: string }
    | { kind: "revocation"; instruction: Record<string, unknown>; evidence: Record<string, unknown> }
    | { kind: "passkey_revoked"; sub: string; credentialId: string };
}

export interface EvidenceApprover {
  sub: string;
  memberOf: string;
  via: "trust-anchor" | "credential";
}

export type EvidenceChainResult =
  | { ok: true; approvers: EvidenceApprover[] }
  | { ok: false; reason: string; depth: number; detail?: string };

export interface HavenWebAuthnEvidence {
  type: "HavenWebAuthnEvidence";
  version: 1;
  kind: "approval" | "endorsement";
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
  approver: { sub: string; memberOf: string; role: "admin" | "member" };
  approverCredential?: string;
  merklePath?: MerklePathElement[];
}

export interface EvidenceOptions {
  resolveDid: ResolveDid;
  /** The trust anchor key log; see `staticKeyLogs`. */
  resolveKeyLog: ResolveKeyLog;
  trustAnchorDid: string;
  /** Verification time, epoch seconds. Default: the system clock. */
  now?: number;
  /** Approver credentials followed below the credential itself. Default 8. */
  maxDepth?: number;
  memberVcts?: readonly string[];
  organisationVcts?: readonly string[];
}

interface Ctx {
  resolveDid: ResolveDid;
  ta: string;
  taDoc: DidDocument;
  keys: TrustAnchorKeys;
  now: number;
  maxDepth: number;
  memberVcts: readonly string[];
  organisationVcts: readonly string[];
}

type Payload = Record<string, unknown>;
type Approver = {
  sub: string;
  memberOf: string;
  role: "admin" | "member";
  via: EvidenceApprover["via"];
};

class Fail extends Error {
  constructor(
    readonly reason: string,
    readonly depth: number,
    readonly detail?: string,
  ) {
    super(reason);
  }
  result(): EvidenceChainResult {
    return {
      ok: false,
      reason: this.reason,
      depth: this.depth,
      ...(this.detail === undefined ? {} : { detail: this.detail }),
    };
  }
}

/** Thrown by `replayTrustAnchorKeyLog`; `reason` is `key-log-invalid`. */
export class KeyLogError extends Error {
  readonly reason = "key-log-invalid";
  constructor(readonly detail: string) {
    super(`key-log-invalid: ${detail}`);
    this.name = "KeyLogError";
  }
}

/** Thrown by `verifyDidSignedJwt`; `reason` is the failure reason. */
export class JwsVerificationError extends Error {
  constructor(
    readonly reason: string,
    readonly detail?: string,
  ) {
    super(detail ? `${reason}: ${detail}` : reason);
    this.name = "JwsVerificationError";
  }
}

// --- digests, identifiers, DID documents ------------------------------------

/** `base64url(SHA-256(UTF-8(JCS(payload without evidence/proof))))`. */
export function payloadDigest(payload: Payload): string {
  return b64urlEncode(payloadDigestBytes(payload));
}

/** The challenge evidence for `payload` must carry: its digest folded up `merklePath`. */
export function evidenceChallenge(payload: Payload, merklePath?: unknown): string {
  return b64urlEncode(foldPath(payloadDigestBytes(payload), merklePath));
}

/** `<ta>#passkey-<b64url(SHA-256(rawId))>`: a trust anchor admin passkey. */
export function passkeyVmId(trustAnchorDid: string, credentialId: string): string {
  const digest = createHash("sha256").update(b64urlDecode(credentialId)).digest();
  return `${trustAnchorDid}#passkey-${b64urlEncode(digest)}`;
}

/** Wrap the four raw WebAuthn values as a `HavenWebAuthnEvidence`. */
export function buildWebAuthnEvidence(
  assertion: Pick<
    HavenWebAuthnEvidence,
    "credentialId" | "authenticatorData" | "clientDataJSON" | "signature"
  >,
  options: {
    approver: HavenWebAuthnEvidence["approver"];
    kind?: HavenWebAuthnEvidence["kind"];
    approverCredential?: string;
    merklePath?: MerklePathElement[];
  },
): HavenWebAuthnEvidence {
  return {
    type: "HavenWebAuthnEvidence",
    version: 1,
    kind: options.kind ?? "approval",
    credentialId: assertion.credentialId,
    authenticatorData: assertion.authenticatorData,
    clientDataJSON: assertion.clientDataJSON,
    signature: assertion.signature,
    approver: { ...options.approver },
    ...(options.approverCredential === undefined
      ? {}
      : { approverCredential: options.approverCredential }),
    ...(options.merklePath && options.merklePath.length > 0
      ? { merklePath: options.merklePath }
      : {}),
  };
}

/** A resolver over a fixed set of DID documents (keyed by DID, or a list). */
export function staticResolver(
  documents: Record<string, DidDocument> | DidDocument[],
): ResolveDid {
  const docs = new Map<string, DidDocument>(
    Array.isArray(documents)
      ? documents.map((d) => [d.id as string, d])
      : Object.entries(documents),
  );
  return async (did) => {
    const doc = docs.get(did);
    if (!doc) throw new Error(`unknown DID ${did}`);
    return structuredClone(doc);
  };
}

/** A key log resolver over a fixed `{ trust anchor DID: entries }` map. */
export function staticKeyLogs(logs: Record<string, unknown>): ResolveKeyLog {
  const map = new Map(Object.entries(logs));
  return async (did) => {
    if (!map.has(did)) throw new Error(`no key log for ${did}`);
    return structuredClone(map.get(did));
  };
}

const didOf = (didUrl: string): string => didUrl.split("#")[0];
const absolute = (doc: DidDocument, id: string): string =>
  id.startsWith("#") ? `${String(doc.id)}${id}` : id;

function findVerificationMethod(
  doc: DidDocument,
  id: string,
  relationship: "assertionMethod" | "authentication",
): Record<string, unknown> | undefined {
  const wanted = absolute(doc, id);
  const refs = Array.isArray(doc[relationship]) ? (doc[relationship] as unknown[]) : [];
  const methods = Array.isArray(doc.verificationMethod)
    ? (doc.verificationMethod as Record<string, unknown>[])
    : [];
  const usable = (m: unknown): m is Record<string, unknown> =>
    !!m &&
    typeof m === "object" &&
    typeof (m as Record<string, unknown>).id === "string" &&
    absolute(doc, (m as Record<string, string>).id) === wanted &&
    !!(m as Record<string, unknown>).publicKeyJwk &&
    typeof (m as Record<string, unknown>).publicKeyJwk === "object" &&
    !Array.isArray((m as Record<string, unknown>).publicKeyJwk);
  for (const ref of refs) {
    if (typeof ref === "string") {
      if (absolute(doc, ref) !== wanted) continue;
      const vm = methods.find(usable);
      if (vm) return vm;
    } else if (usable(ref)) {
      return ref;
    }
  }
  return undefined;
}

async function resolveExact(resolveDid: ResolveDid, did: string): Promise<DidDocument> {
  const doc = await resolveDid(did);
  if (!doc || doc.id !== did) {
    throw new Error(`resolved document id does not match ${did}`);
  }
  return doc;
}

function readRelyingParty(taDoc: DidDocument): { rpId: string; origins: string[] } | undefined {
  const services = Array.isArray(taDoc.service) ? (taDoc.service as Record<string, unknown>[]) : [];
  const service = services.find((s) => s && s.type === RELYING_PARTY_SERVICE_TYPE);
  const endpoint = service?.serviceEndpoint as Record<string, unknown> | undefined;
  if (!endpoint || typeof endpoint !== "object" || Array.isArray(endpoint)) return undefined;
  const { rpId, origins } = endpoint;
  if (typeof rpId !== "string" || !rpId) return undefined;
  if (!Array.isArray(origins) || !origins.every((o) => typeof o === "string")) return undefined;
  return { rpId, origins: origins as string[] };
}

// --- keys and signatures ----------------------------------------------------

function jwsAlgFits(alg: string, jwk: Jwk): boolean {
  if (alg === "ES256") return jwk.kty === "EC" && jwk.crv === "P-256";
  if (alg === "EdDSA" || alg === "Ed25519") return jwk.kty === "OKP" && jwk.crv === "Ed25519";
  return false;
}

/** DER → raw `r ‖ s` (32 bytes each). Tolerates redundant leading zeros, rejects trailing bytes. */
export function derToRaw(der: Uint8Array, size = 32): Uint8Array {
  const length = (at: number): [number, number] => {
    const first = der[at];
    if (first === undefined) throw new TypeError("truncated DER");
    if (first < 0x80) return [first, at + 1];
    const n = der[at + 1];
    if (first !== 0x81 || n === undefined || n < 0x80) {
      throw new TypeError("unsupported DER length");
    }
    return [n, at + 2];
  };
  const integer = (at: number): [Uint8Array, number] => {
    if (der[at] !== 0x02) throw new TypeError("expected DER INTEGER");
    const [n, start] = length(at + 1);
    const end = start + n;
    if (n === 0 || end > der.length) throw new TypeError("truncated DER INTEGER");
    let value = der.subarray(start, end);
    while (value.length > 1 && value[0] === 0) value = value.subarray(1);
    if (value.length > size) throw new TypeError("DER INTEGER too large");
    const out = new Uint8Array(size);
    out.set(value, size - value.length);
    return [out, end];
  };
  if (der[0] !== 0x30) throw new TypeError("expected DER SEQUENCE");
  const [n, start] = length(1);
  if (start + n !== der.length) throw new TypeError("DER SEQUENCE length mismatch");
  const [r, afterR] = integer(start);
  const [s, afterS] = integer(afterR);
  if (afterS !== der.length) throw new TypeError("trailing bytes after DER signature");
  const raw = new Uint8Array(2 * size);
  raw.set(r, 0);
  raw.set(s, size);
  return raw;
}

/**
 * Verify a compact JWS (or the issuer JWT of an SD-JWT) against the key its
 * `kid` names under `assertionMethod` in the `iss` DID document. Throws
 * `JwsVerificationError` with the failure reason.
 */
export async function verifyDidSignedJwt(
  token: string,
  options: { resolveDid: ResolveDid; typ?: string },
): Promise<{ header: Record<string, unknown>; payload: Payload }> {
  const typ = options.typ ?? CREDENTIAL_JWT_TYP;
  const jws = typeof token === "string" ? token.split("~")[0] : "";
  const parts = jws.split(".");
  let header: Record<string, unknown>;
  let payload: unknown;
  try {
    if (parts.length !== 3) throw new Error();
    header = decodeProtectedHeader(jws) as Record<string, unknown>;
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(b64urlDecode(parts[1])));
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error();
  } catch {
    throw new JwsVerificationError("malformed-credential", "not a compact JWS");
  }
  const claims = payload as Payload;
  if (header.typ !== typ) throw new JwsVerificationError("unexpected-typ", String(header.typ));
  const alg = header.alg;
  if (typeof alg !== "string" || !SUPPORTED_JWS_ALGS.has(alg)) {
    throw new JwsVerificationError("unsupported-alg", String(alg));
  }
  const iss = claims.iss;
  if (typeof iss !== "string" || !iss.startsWith("did:")) {
    throw new JwsVerificationError("malformed-credential");
  }
  const kid =
    typeof header.kid === "string"
      ? header.kid.startsWith("#")
        ? `${iss}${header.kid}`
        : header.kid
      : "";
  if (!kid || didOf(kid) !== iss) {
    throw new JwsVerificationError("issuer-key-not-found", "kid is not a key of iss");
  }
  let doc: DidDocument;
  try {
    doc = await resolveExact(options.resolveDid, iss);
  } catch (e) {
    throw new JwsVerificationError("did-resolution-failed", (e as Error).message);
  }
  const vm = findVerificationMethod(doc, kid, "assertionMethod");
  if (!vm) throw new JwsVerificationError("issuer-key-not-found", kid);
  const jwk = vm.publicKeyJwk as Jwk;
  if (!jwsAlgFits(alg, jwk)) throw new JwsVerificationError("unsupported-alg", alg);
  try {
    const key = await importJWK({ ...jwk } as Parameters<typeof importJWK>[0], alg);
    await compactVerify(jws, key, { algorithms: [alg] });
  } catch (e) {
    throw new JwsVerificationError("bad-issuer-signature", (e as Error).message);
  }
  return { header: { ...header, kid }, payload: claims };
}

// --- WebAuthn assertion checks (spec §4 steps 2, 3, 4, 6) -------------------

function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

function checkClientData(
  e: HavenWebAuthnEvidence,
  challenge: string,
  origins: string[],
  depth: number,
): void {
  let cd: Record<string, unknown>;
  try {
    cd = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(b64urlDecode(e.clientDataJSON)));
  } catch {
    throw new Fail("client-data-invalid", depth, "clientDataJSON is not JSON");
  }
  if (!cd || typeof cd !== "object") throw new Fail("client-data-invalid", depth);
  if (cd.type !== "webauthn.get") {
    throw new Fail("client-data-invalid", depth, `type ${String(cd.type)}`);
  }
  if (
    typeof cd.challenge !== "string" ||
    !sameBytes(Buffer.from(cd.challenge), Buffer.from(challenge))
  ) {
    throw new Fail("digest-mismatch", depth);
  }
  if (cd.crossOrigin === true) throw new Fail("cross-origin", depth);
  if (typeof cd.origin !== "string" || !origins.includes(cd.origin)) {
    throw new Fail("origin-not-allowed", depth, String(cd.origin));
  }
}

function checkAuthenticatorData(e: HavenWebAuthnEvidence, rpId: string, depth: number): void {
  let ad: Uint8Array;
  try {
    ad = b64urlDecode(e.authenticatorData);
  } catch {
    throw new Fail("authenticator-data-invalid", depth);
  }
  if (ad.length < 37) throw new Fail("authenticator-data-invalid", depth, "shorter than 37 bytes");
  if (!sameBytes(ad.subarray(0, 32), sha256(new TextEncoder().encode(rpId)))) {
    throw new Fail("rp-id-hash-mismatch", depth);
  }
  if (!(ad[32] & FLAG_UP)) throw new Fail("user-not-present", depth);
  if (!(ad[32] & FLAG_UV)) throw new Fail("user-not-verified", depth);
}

async function verifyAssertionSignature(
  e: HavenWebAuthnEvidence,
  jwk: Jwk,
  depth: number,
): Promise<void> {
  const subtle = globalThis.crypto.subtle;
  let data: Uint8Array;
  let signature: Uint8Array;
  try {
    const ad = b64urlDecode(e.authenticatorData);
    const cdHash = sha256(b64urlDecode(e.clientDataJSON));
    data = new Uint8Array(ad.length + cdHash.length);
    data.set(ad, 0);
    data.set(cdHash, ad.length);
    signature = b64urlDecode(e.signature);
  } catch {
    throw new Fail("malformed-evidence", depth);
  }
  const alg = jwk.alg;
  try {
    if (jwk.kty === "EC" && jwk.crv === "P-256" && (alg === undefined || alg === "ES256")) {
      let raw: Uint8Array;
      try {
        raw = derToRaw(signature, 32);
      } catch (err) {
        throw new Fail("bad-webauthn-signature", depth, (err as Error).message);
      }
      const key = await subtle.importKey(
        "jwk",
        { kty: "EC", crv: "P-256", x: jwk.x as string, y: jwk.y as string },
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      const ok = await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(raw), new Uint8Array(data));
      if (!ok) throw new Fail("bad-webauthn-signature", depth);
      return;
    }
    if (jwk.kty === "OKP" && jwk.crv === "Ed25519" && (alg === undefined || alg === "EdDSA")) {
      const key = await subtle.importKey(
        "jwk",
        { kty: "OKP", crv: "Ed25519", x: jwk.x as string },
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      const ok = await subtle.verify({ name: "Ed25519" }, key, new Uint8Array(signature), new Uint8Array(data));
      if (!ok) throw new Fail("bad-webauthn-signature", depth);
      return;
    }
  } catch (err) {
    if (err instanceof Fail) throw err;
    throw new Fail("bad-webauthn-signature", depth, (err as Error).message);
  }
  throw new Fail("unsupported-alg", depth, `${String(jwk.kty)}/${String(jwk.crv)}/${String(jwk.alg)}`);
}

// --- the chain (spec §4) ----------------------------------------------------

const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;
// A JSON integer: integral and inside the IEEE 754 safe range, so that both
// runtimes accept the same values (JSON.parse cannot tell 1 from 1.0 and loses
// precision beyond 2^53; JCS serialises both forms identically).
const isInt = (v: unknown): v is number => Number.isSafeInteger(v);
const isObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);

function parseEvidence(e: unknown, depth: number): HavenWebAuthnEvidence {
  const o = e as Record<string, unknown>;
  const approver = o?.approver as Record<string, unknown> | undefined;
  const ok =
    !!o &&
    typeof o === "object" &&
    !Array.isArray(o) &&
    o.type === EVIDENCE_TYPE &&
    o.version === 1 &&
    (o.kind === "approval" || o.kind === "endorsement") &&
    ["credentialId", "authenticatorData", "clientDataJSON", "signature"].every(
      (k) => typeof o[k] === "string" && B64URL_NONEMPTY.test(o[k] as string),
    ) &&
    !!approver &&
    typeof approver === "object" &&
    isStr(approver.sub) &&
    isStr(approver.memberOf) &&
    (approver.role === "admin" || approver.role === "member") &&
    (!("approverCredential" in o) || isStr(o.approverCredential));
  if (!ok) throw new Fail("malformed-evidence", depth);
  return o as unknown as HavenWebAuthnEvidence;
}

function parseInstruction(instruction: unknown): Payload & { actor: string; issuedAt: number } {
  const i = instruction as Record<string, unknown>;
  const ok =
    !!i &&
    typeof i === "object" &&
    !Array.isArray(i) &&
    i["@context"] === INSTRUCTION_CONTEXT &&
    INSTRUCTION_TYPES.includes(i.type as string) &&
    isStr(i.tenant) &&
    typeof i.credential === "string" &&
    URN_UUID.test(i.credential) &&
    typeof i.entry === "string" &&
    CRSET_ENTRY_ID.test(i.entry) &&
    isStr(i.actor) &&
    isInt(i.issuedAt) &&
    isStr(i.nonce);
  if (!ok) throw new Fail("malformed-instruction", 0);
  return i as Payload & { actor: string; issuedAt: number };
}

function memberFields(p: Payload): { org: string; role: "admin" | "member" } | undefined {
  const memberOf = p.memberOf;
  const valid =
    isStr(memberOf) ||
    (Array.isArray(memberOf) && memberOf.length > 0 && memberOf.every((m) => isStr(m)));
  if (!valid || (p.role !== "admin" && p.role !== "member")) return undefined;
  return { org: typeof memberOf === "string" ? memberOf : (memberOf as string[])[0], role: p.role };
}

// --- the trust anchor key log (spec §4.5) -----------------------------------

type KeyLogOp =
  | {
      at: number;
      kind: "credential";
      sub: string;
      role: "admin" | "member";
      jti: string;
      iat: number;
      exp: number;
      authenticators: Map<string, Jwk>;
    }
  | { at: number; kind: "revocation"; credential: string }
  | { at: number; kind: "passkey_revoked"; sub: string; credentialId: string };

/**
 * A replayed trust anchor key log. `credentialJtis` holds the `jti` of every
 * `credential` entry; `keysAt` gives the admin passkeys active at an instant.
 */
export class TrustAnchorKeys {
  constructor(
    private readonly ops: readonly KeyLogOp[],
    readonly credentialJtis: ReadonlySet<string>,
  ) {}

  /**
   * `credentialId -> { sub, jwk }` for every admin passkey active at `t`:
   * entries with `at <= t` applied in order, then admins whose credential does
   * not cover `t` (`iat <= t <= exp`) dropped.
   */
  keysAt(t: number): Map<string, { sub: string; jwk: Jwk }> {
    const admins = new Map<
      string,
      { jti: string; iat: number; exp: number; authenticators: Map<string, Jwk> }
    >();
    for (const op of this.ops) {
      if (op.at > t) break;
      if (op.kind === "credential") {
        admins.delete(op.sub);
        if (op.role === "admin") {
          admins.set(op.sub, {
            jti: op.jti,
            iat: op.iat,
            exp: op.exp,
            authenticators: new Map(op.authenticators),
          });
        }
      } else if (op.kind === "revocation") {
        for (const [sub, record] of [...admins]) {
          if (record.jti === op.credential) admins.delete(sub);
        }
      } else {
        admins.get(op.sub)?.authenticators.delete(op.credentialId);
      }
    }
    const keys = new Map<string, { sub: string; jwk: Jwk }>();
    for (const [sub, record] of admins) {
      if (!(record.iat <= t && t <= record.exp)) continue;
      for (const [credentialId, jwk] of record.authenticators) {
        // The admin whose credential entry came later wins.
        keys.delete(credentialId);
        keys.set(credentialId, { sub, jwk });
      }
    }
    return keys;
  }
}

/** `b64url(SHA-256(JCS({ seq, kind, at, prev, material })))`. */
export function keyLogEntryHash(entry: Record<string, unknown>): string {
  const pick = (k: string) => (entry[k] === undefined ? null : entry[k]);
  return payloadDigest({
    seq: pick("seq"),
    kind: pick("kind"),
    at: pick("at"),
    prev: pick("prev"),
    material: pick("material"),
  });
}

async function keyLogCredential(
  material: Record<string, unknown>,
  ta: string,
  resolveDid: ResolveDid,
  memberVcts: readonly string[],
): Promise<Extract<KeyLogOp, { kind: "credential" }> | string> {
  const jwt = material.jwt;
  if (typeof jwt !== "string" || !jwt.endsWith("~") || jwt.split("~").length !== 2) {
    return "credential jwt is not an issuer JWT with a trailing ~";
  }
  let p: Payload;
  try {
    ({ payload: p } = await verifyDidSignedJwt(jwt, { resolveDid }));
  } catch (err) {
    if (err instanceof JwsVerificationError) return `credential ${err.reason}`;
    throw err;
  }
  const fields = memberFields(p);
  if (
    p.iss !== ta ||
    !memberVcts.includes(p.vct as string) ||
    !fields ||
    fields.org !== ta ||
    !isStr(p.sub) ||
    !isStr(p.jti) ||
    !isInt(p.iat) ||
    !isInt(p.exp) ||
    !Array.isArray(p.authenticators)
  ) {
    return "credential is not a trust anchor member credential";
  }
  const authenticators = new Map<string, Jwk>();
  for (const a of p.authenticators as unknown[]) {
    if (!isObject(a) || !isStr(a.credentialId) || !isObject(a.jwk)) {
      return "credential has a malformed authenticator";
    }
    authenticators.set(a.credentialId, a.jwk as Jwk);
  }
  return {
    at: 0,
    kind: "credential",
    sub: p.sub,
    role: fields.role,
    jti: p.jti,
    iat: p.iat,
    exp: p.exp,
    authenticators,
  };
}

/**
 * Check the chain of a trust anchor key log and replay it. Throws
 * `KeyLogError` on the first violation: `seq` not 1-based and gap-free, a
 * wrong `prev` or `hash`, `at` decreasing, a malformed entry, or a
 * `credential` entry that is not a trust anchor member credential signed by
 * the trust anchor. The evidence of the logged credentials is not
 * chain-verified: the log is the authority.
 */
export async function replayTrustAnchorKeyLog(
  entries: unknown,
  options: { trustAnchorDid: string; resolveDid: ResolveDid; memberVcts?: readonly string[] },
): Promise<TrustAnchorKeys> {
  const memberVcts = options.memberVcts ?? MEMBER_VCTS;
  if (!Array.isArray(entries)) throw new KeyLogError("the key log is not an array");
  const ops: KeyLogOp[] = [];
  const jtis = new Set<string>();
  let prevHash: string | null = null;
  let prevAt: number | undefined;
  for (const [i, entry] of entries.entries()) {
    const invalid = (detail: string) => new KeyLogError(`entry ${i + 1}: ${detail}`);
    if (
      !isObject(entry) ||
      !isInt(entry.seq) ||
      !KEY_LOG_KINDS.includes(entry.kind as string) ||
      !isInt(entry.at) ||
      !(entry.prev === null || isStr(entry.prev)) ||
      !isStr(entry.hash) ||
      !isObject(entry.material) ||
      entry.material.kind !== entry.kind
    ) {
      throw invalid("malformed entry");
    }
    if (entry.seq !== i + 1) throw invalid(`seq ${entry.seq}`);
    if (entry.prev !== prevHash) throw invalid("prev is not the hash of the previous entry");
    if (keyLogEntryHash(entry) !== entry.hash) throw invalid("hash does not match");
    if (prevAt !== undefined && entry.at < prevAt) throw invalid("at decreases");
    const material = entry.material;
    const at = entry.at;
    if (entry.kind === "credential") {
      const data = await keyLogCredential(material, options.trustAnchorDid, options.resolveDid, memberVcts);
      if (typeof data === "string") throw invalid(data);
      jtis.add(data.jti);
      ops.push({ ...data, at });
    } else if (entry.kind === "revocation") {
      const instruction = material.instruction;
      if (!isObject(instruction) || !isStr(instruction.credential) || !isObject(material.evidence)) {
        throw invalid("malformed revocation");
      }
      ops.push({ at, kind: "revocation", credential: instruction.credential });
    } else {
      if (!isStr(material.sub) || !isStr(material.credentialId)) {
        throw invalid("malformed passkey_revoked");
      }
      ops.push({ at, kind: "passkey_revoked", sub: material.sub, credentialId: material.credentialId });
    }
    prevHash = entry.hash;
    prevAt = at;
  }
  return new TrustAnchorKeys(ops, jtis);
}

/**
 * The bootstrap rule of step 5.1: a trust anchor admin member credential
 * approved by its own subject's passkey while no admin key is active.
 */
function bootstrapKey(
  e: HavenWebAuthnEvidence,
  p: Payload | undefined,
  active: Map<string, unknown>,
  ctx: Ctx,
  unsigned: boolean,
): Jwk | undefined {
  if (!p || active.size > 0) return undefined;
  const fields = memberFields(p);
  if (
    p.iss !== ctx.ta ||
    !ctx.memberVcts.includes(p.vct as string) ||
    fields?.org !== ctx.ta ||
    fields.role !== "admin" ||
    e.approver.sub !== p.sub ||
    !Array.isArray(p.authenticators)
  ) {
    return undefined;
  }
  const match = (p.authenticators as unknown[]).find(
    (a): a is Record<string, unknown> => isObject(a) && a.credentialId === e.credentialId,
  );
  if (!match || !isObject(match.jwk)) return undefined;
  // A signed credential must be in the log; the issuer's pre-signing check
  // runs before it appends that entry.
  if (!unsigned && !ctx.keys.credentialJtis.has(p.jti as string)) return undefined;
  return match.jwk as Jwk;
}

function challengeFor(payload: Payload, e: HavenWebAuthnEvidence, depth: number): string {
  try {
    return evidenceChallenge(payload, e.merklePath);
  } catch (err) {
    if (err instanceof MerklePathError) throw new Fail("malformed-evidence", depth, err.message);
    throw err;
  }
}

async function verifyAssertion(
  e: HavenWebAuthnEvidence,
  challenge: string,
  anchorTime: number,
  ctx: Ctx,
  depth: number,
  subject?: Payload,
  unsigned = false,
): Promise<{ approver: Approver; approverCredential?: Payload }> {
  const rp = readRelyingParty(ctx.taDoc);
  if (!rp) throw new Fail("relying-party-missing", depth);
  checkClientData(e, challenge, rp.origins, depth);
  checkAuthenticatorData(e, rp.rpId, depth);

  let key: Jwk | undefined;
  let approver: Approver | undefined;
  let approverCredential: Payload | undefined;

  // 5.1 only for an approval without an approver credential. An endorsement
  // must prove who the subject is, and an approver who carries a member
  // credential acts for that credential's organisation, even when the passkey
  // is also a trust anchor admin passkey. The key comes from the key log as
  // of the anchor time, never from the trust anchor document.
  if (e.kind === "approval" && !e.approverCredential) {
    const active = ctx.keys.keysAt(anchorTime);
    const found = active.get(e.credentialId);
    let sub: string;
    if (found) {
      ({ sub, jwk: key } = found);
    } else {
      key = bootstrapKey(e, subject, active, ctx, unsigned);
      if (!key) throw new Fail("approver-key-not-found", depth, "not a trust anchor admin passkey at iat");
      sub = subject!.sub as string;
    }
    if (e.approver.sub !== sub || e.approver.memberOf !== ctx.ta || e.approver.role !== "admin") {
      throw new Fail("approver-mismatch", depth, "key is a trust anchor passkey");
    }
    approver = { sub, memberOf: ctx.ta, role: "admin", via: "trust-anchor" };
  }

  // 5.2
  if (!key) {
    if (!e.approverCredential) throw new Fail("approver-credential-missing", depth);
    if (depth + 1 > ctx.maxDepth) throw new Fail("depth-exceeded", depth + 1);
    let ac: Payload;
    try {
      ({ payload: ac } = await verifyDidSignedJwt(e.approverCredential, { resolveDid: ctx.resolveDid }));
    } catch (err) {
      if (err instanceof JwsVerificationError) throw new Fail(err.reason, depth + 1, err.detail);
      throw err;
    }
    if (!ctx.memberVcts.includes(ac.vct as string)) {
      throw new Fail("approver-credential-not-member", depth + 1, String(ac.vct));
    }
    const fields = memberFields(ac);
    if (!fields || !isStr(ac.sub) || !isInt(ac.iat) || !isInt(ac.exp) || !Array.isArray(ac.authenticators)) {
      throw new Fail("malformed-credential", depth + 1);
    }
    if (!(ac.iat <= anchorTime && anchorTime <= ac.exp)) {
      throw new Fail("approver-credential-out-of-window", depth);
    }
    const match = (ac.authenticators as { credentialId?: unknown; jwk?: unknown }[]).find(
      (a) => a && a.credentialId === e.credentialId,
    );
    if (!match || !match.jwk || typeof match.jwk !== "object" || Array.isArray(match.jwk)) {
      throw new Fail("approver-key-not-found", depth);
    }
    approver = { sub: ac.sub, memberOf: fields.org, role: fields.role, via: "credential" };
    if (
      e.approver.sub !== approver.sub ||
      e.approver.memberOf !== approver.memberOf ||
      e.approver.role !== approver.role
    ) {
      throw new Fail("approver-mismatch", depth);
    }
    key = match.jwk as Jwk;
    approverCredential = ac;
  }

  await verifyAssertionSignature(e, key, depth);
  return { approver: approver as Approver, approverCredential };
}

/** Step 7: may this approver authorise this credential? */
function checkAuthority(p: Payload, e: HavenWebAuthnEvidence, approver: Approver, ctx: Ctx, depth: number): void {
  const isTaAdmin =
    approver.role === "admin" && (approver.via === "trust-anchor" || approver.memberOf === ctx.ta);

  if (ctx.organisationVcts.includes(p.vct as string)) {
    if (p.iss !== ctx.ta) throw new Fail("issuer-not-trust-anchor", depth);
    if (e.kind === "endorsement") {
      throw new Fail("endorsement-subject-mismatch", depth, "organisation-level credential");
    }
    if (approver.role !== "admin") throw new Fail("approver-not-admin", depth);
    if (!isTaAdmin) throw new Fail("approver-not-trust-anchor", depth);
    return;
  }

  const fields = memberFields(p);
  if (!fields) throw new Fail("malformed-credential", depth);
  if (p.iss !== fields.org) throw new Fail("issuer-not-organisation", depth);

  if (e.kind === "endorsement") {
    if (approver.via !== "credential" || approver.sub !== p.sub || approver.memberOf !== fields.org) {
      throw new Fail("endorsement-subject-mismatch", depth);
    }
    if (approver.role !== fields.role) {
      throw new Fail("endorsement-subject-mismatch", depth, "role differs");
    }
    return;
  }

  if (approver.role !== "admin") throw new Fail("approver-not-admin", depth);
  if (fields.org === ctx.ta) {
    if (!isTaAdmin) throw new Fail("approver-not-trust-anchor", depth);
    return;
  }
  if (approver.memberOf === fields.org) return;
  // A trust anchor admin seats an organisation's admins, never its members.
  if (isTaAdmin && fields.role === "admin") return;
  throw new Fail(
    "approver-wrong-organisation",
    depth,
    isTaAdmin ? "trust anchor admin approving a member role" : undefined,
  );
}

async function verifyPayloadChain(
  p: Payload,
  ctx: Ctx,
  depth: number,
  unsigned = false,
): Promise<EvidenceApprover[]> {
  if (depth > ctx.maxDepth) throw new Fail("depth-exceeded", depth);
  if (!isStr(p.iss) || !isStr(p.sub) || !isInt(p.iat) || !isInt(p.exp) || !Array.isArray(p.evidence)) {
    throw new Fail("malformed-credential", depth);
  }
  if (p.iat > ctx.now + CLOCK_SKEW_SECONDS) throw new Fail("issued-in-future", depth);
  const vct = p.vct as string;
  if (!ctx.memberVcts.includes(vct) && !ctx.organisationVcts.includes(vct)) {
    throw new Fail("unknown-vct", depth, String(p.vct));
  }

  // The trust anchor's own organisation credential is the root.
  if (p.evidence.length === 0 && p.iss === ctx.ta && p.sub === ctx.ta && ctx.organisationVcts.includes(vct)) {
    return [];
  }
  if (p.evidence.length !== 1) throw new Fail("evidence-count", depth);

  const e = parseEvidence(p.evidence[0], depth);
  const { approver, approverCredential } = await verifyAssertion(
    e,
    challengeFor(p, e, depth),
    p.iat,
    ctx,
    depth,
    p,
    unsigned,
  );
  checkAuthority(p, e, approver, ctx, depth);
  if (e.kind === "endorsement") {
    // §4 step 7: a self-endorsement only updates passkeys and reissue metadata.
    const mutable = new Set(["authenticators", "iat", "jti", "evidence"]);
    const fixed = (payload: Payload) =>
      Object.fromEntries(Object.entries(payload).filter(([key]) => !mutable.has(key)));
    if (canonicalize(fixed(approverCredential!)) !== canonicalize(fixed(p))) {
      throw new Fail("endorsement-payload-mismatch", depth);
    }
  }

  const approvers: EvidenceApprover[] = [
    { sub: approver.sub, memberOf: approver.memberOf, via: approver.via },
  ];
  if (approverCredential) {
    approvers.push(...(await verifyPayloadChain(approverCredential, ctx, depth + 1)));
  }
  return approvers;
}

async function context(options: EvidenceOptions): Promise<Ctx> {
  let taDoc: DidDocument;
  try {
    taDoc = await resolveExact(options.resolveDid, options.trustAnchorDid);
  } catch (e) {
    throw new Fail("did-resolution-failed", 0, (e as Error).message);
  }
  const memberVcts = options.memberVcts ?? MEMBER_VCTS;
  let entries: unknown;
  try {
    entries = await options.resolveKeyLog(options.trustAnchorDid);
  } catch (e) {
    throw new Fail("key-log-unavailable", 0, (e as Error).message);
  }
  let keys: TrustAnchorKeys;
  try {
    keys = await replayTrustAnchorKeyLog(entries, {
      trustAnchorDid: options.trustAnchorDid,
      resolveDid: options.resolveDid,
      memberVcts,
    });
  } catch (e) {
    if (e instanceof KeyLogError) throw new Fail(e.reason, 0, e.detail);
    throw e;
  }
  return {
    resolveDid: options.resolveDid,
    ta: options.trustAnchorDid,
    taDoc,
    keys,
    now: options.now ?? Math.floor(Date.now() / 1000),
    maxDepth: options.maxDepth ?? DEFAULT_MAX_EVIDENCE_DEPTH,
    memberVcts,
    organisationVcts: options.organisationVcts ?? ORGANISATION_VCTS,
  };
}

async function run(fn: () => Promise<EvidenceApprover[]>): Promise<EvidenceChainResult> {
  try {
    return { ok: true, approvers: await fn() };
  } catch (err) {
    if (err instanceof Fail) return err.result();
    throw err;
  }
}

/**
 * Verify a credential's evidence chain up to the trust anchor. `issuerJwt` is
 * the issuer JWT or the whole SD-JWT. Does not check expiry or revocation.
 */
export async function verifyEvidenceChain(
  issuerJwt: string,
  options: EvidenceOptions,
): Promise<EvidenceChainResult> {
  return run(async () => {
    const ctx = await context(options);
    let payload: Payload;
    try {
      ({ payload } = await verifyDidSignedJwt(issuerJwt, { resolveDid: options.resolveDid }));
    } catch (err) {
      if (err instanceof JwsVerificationError) throw new Fail(err.reason, 0, err.detail);
      throw err;
    }
    return verifyPayloadChain(payload, ctx, 0);
  });
}

/**
 * The issuer's check before it signs: `evidence` against the unsigned
 * `payload` (without an `evidence` member). Same result as
 * `verifyEvidenceChain` once signed with `evidence: [evidence]`.
 */
export async function verifyEvidenceForPayload(
  payload: Payload,
  evidence: unknown,
  options: EvidenceOptions,
): Promise<EvidenceChainResult> {
  if ("evidence" in payload) {
    return { ok: false, reason: "malformed-credential", depth: 0, detail: "the payload already carries evidence" };
  }
  return run(async () =>
    verifyPayloadChain({ ...payload, evidence: [evidence] }, await context(options), 0, true),
  );
}

/**
 * Evidence for an action that is not an issuance (`haven:RevokeCredential`):
 * the approver must be the instruction's `actor`. Who may revoke what is the
 * caller's policy.
 */
export async function verifyInstructionEvidence(
  instruction: unknown,
  evidence: unknown,
  options: EvidenceOptions,
): Promise<EvidenceChainResult> {
  return run(async () => {
    const instr = parseInstruction(instruction);
    const e = parseEvidence(evidence, 0);
    if (e.kind !== "approval") throw new Fail("malformed-evidence", 0, "instructions take approval evidence");
    if (e.approver.sub !== instr.actor) throw new Fail("approver-mismatch", 0, "approver is not the actor");
    const ctx = await context(options);
    const { approver, approverCredential } = await verifyAssertion(
      e,
      challengeFor(instr, e, 0),
      instr.issuedAt,
      ctx,
      0,
    );
    const approvers: EvidenceApprover[] = [
      { sub: approver.sub, memberOf: approver.memberOf, via: approver.via },
    ];
    if (approverCredential) approvers.push(...(await verifyPayloadChain(approverCredential, ctx, 1)));
    return approvers;
  });
}
