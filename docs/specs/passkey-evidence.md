# Passkey Evidence Specification

**Version**: 1.1.0
**Status**: Draft
**Evidence type**: `HavenWebAuthnEvidence` (version 1)
**Implementations**: `harbour.evidence` / `harbour.merkle` (Python),
`evidence.ts` / `merkle.ts` (TypeScript)

---

## 1. Overview

A Harbour credential carries two signatures that mean different things:

| Signature | Made by | Proves |
|-----------|---------|--------|
| **Proof**: the issuer JWT signature | The issuer's signing key, held by the signing service | The issuer published this payload |
| **Evidence**: a WebAuthn assertion inside the payload | The passkey of the person who approved it | A named person decided this payload should exist |

The signing service only performs cryptography; it never decides. Evidence
makes that checkable: a stolen or misused signing key can produce a validly
signed credential, but not a passkey assertion from an approver. A verifier
follows the evidence from approver to approver up to a passkey that the trust
anchor's key log (§4.5) lists as a trust anchor admin passkey at the time of
the approval.

This document specifies the evidence object, how to verify a chain of it, and
how one passkey assertion can approve a whole batch of credentials (§5). It is
written for independent verifiers: everything here can be implemented without
the Harbour libraries.

Conventions: all binary values are base64url without padding. All hashes are
SHA-256. JCS is the RFC 8785 JSON Canonicalization Scheme. WebAuthn refers to
[W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/).

## 2. Identifiers and documents

A brand tenant publishes `did:web` documents under one host:

| Party | DID | Issues |
|-------|-----|--------|
| Service | `did:web:<host>` | Email credentials; operates the revocation registry |
| Trust anchor | `did:web:<host>:participants:<slug>` | Organisation credentials |
| Organisation | `did:web:<host>:participants:<slug>` | Its members' credentials |

Every one of these documents lists the tenant's signing keys under
`assertionMethod` with ids `<did>#key-<RFC 7638 thumbprint>`. A person is
identified by `sub = urn:uuid:<uuid>`, which is never resolved.

The trust anchor document additionally carries:

- one service of type `HavenWebAuthnRelyingParty` whose `serviceEndpoint` is
  `{ "rpId": "<WebAuthn RP ID>", "origins": ["https://..."] }`;
- one service `{ "id": "<ta>#key-log", "type": "HavenTrustAnchorKeyLog",
  "serviceEndpoint": "<url>" }`; `GET <url>` answers `{ "entries": [...] }`,
  the trust anchor key log of §4.5;
- for people and tooling, the current passkeys of the trust anchor admins as
  verification methods with id
  `<trust anchor DID>#passkey-<base64url(SHA-256(rawId))>` and a
  `publicKeyJwk`, referenced from `authentication`. This list is
  informational only: no verifier reads keys from it. The key of a trust
  anchor admin comes from the key log, as of the time of the approval.

Credentials are SD-JWT VCs ([SD-JWT-VC]) with the issuer JWT header
`{ "alg": "ES256", "typ": "dc+sd-jwt", "kid": "<iss>#key-..." }`. Member
credentials carry `memberOf`, `role` (`admin` or `member`) and
`authenticators` (the person's passkeys, `[{ "credentialId", "jwk" }]`) in the
clear. `memberOf` is the organisation DID, or an array whose first element is
the organisation DID.

| Family | `vct` values (default profile) |
|--------|------------------------------|
| Member | `haven:MemberCredential`, `simpulseid:UserCredential`, `simpulseid:AdministratorCredential` |
| Organisation | `haven:OrganisationCredential`, `simpulseid:ParticipantCredential`, `simpulseid:AscsBaseMembershipCredential`, `simpulseid:AscsEnvitedMembershipCredential` |

The implementations take these lists as parameters and use the ones above by
default.

## 3. The payload digest

The digest of an object `p` is

```text
digest(p) = base64url(SHA-256(UTF-8(JCS(p without its top-level "evidence" and "proof"))))
```

For a credential, `p` is the payload of the issuer JWT **exactly as signed**,
including `_sd`, `_sd_alg`, `cnf`, `credentialStatus`, `iat` and `exp`.
Disclosures do not enter the digest, so it can be recomputed from the issuer
JWT alone, whatever the holder chose to disclose. The issuer therefore fixes
the disclosure salts before asking for approval (`build_sd_jwt_payload` /
`buildSdJwtPayload`), and signs that same payload afterwards.

For an action that is not an issuance, `p` is an **instruction** object:

```json
{
  "@context": "https://schema.reachhaven.com/instructions/v1",
  "type": "haven:RevokeCredential",
  "tenant": "<tenant id>",
  "credential": "urn:uuid:<jti of the credential>",
  "entry": "0x<the credential's CRSetEntry id>",
  "actor": "urn:uuid:<person acting>",
  "issuedAt": 1800000000,
  "nonce": "<random>"
}
```

## 4. Evidence

### 4.1 The evidence object

`evidence` is an array holding exactly one object:

```json
{
  "type": "HavenWebAuthnEvidence",
  "version": 1,
  "kind": "approval",
  "credentialId": "<WebAuthn rawId>",
  "authenticatorData": "<raw authenticatorData>",
  "clientDataJSON": "<raw clientDataJSON>",
  "signature": "<raw assertion signature>",
  "approver": { "sub": "urn:uuid:...", "memberOf": "<org or trust anchor DID>", "role": "admin" },
  "approverCredential": "<issuer JWT of the approver's member credential>~",
  "merklePath": [{ "hash": "<32 bytes>", "position": "left" }]
}
```

- `kind` is `approval`, or `endorsement` when a person's own existing passkey
  approves a reissue of their own credential that only changes
  `authenticators`. For an endorsement `approver.role` is the person's own role.
- `approverCredential` is omitted when the approver acts as a trust anchor
  admin through a passkey of the trust anchor key log (§4.5). A trust anchor
  admin who also administers another organisation includes the member
  credential of that organisation to act for it.
- `merklePath` is present only when one assertion approved several payloads
  (§5). Absent, `null` and `[]` all mean a batch of one.
- The evidence is not covered by the digest; it is covered by the issuer
  signature.
- Verifiers ignore members they do not know.

The one exception is the trust anchor's own organisation credential (`iss` and
`sub` both the trust anchor DID). It has `evidence: []` and is the root of every
chain.

### 4.2 The challenge

The WebAuthn challenge the approver signed is

```text
challenge(p, E) = fold(SHA-256 bytes of digest(p), E.merklePath)
```

where `fold` is defined in §5.2 and returns its first argument unchanged when
there is no path. `clientDataJSON.challenge` is the base64url form of these 32
bytes, so for single-payload evidence it equals `digest(p)`.

### 4.3 Verifying an evidence chain

Inputs: the issuer JWT of the credential, the trust anchor DID the verifier
trusts, a DID resolver, the key log of the trust anchor (§4.5), and the current
time. Resolve the trust anchor document, fetch the key log and replay it
first: a log that cannot be fetched fails with `key-log-unavailable`, a log
that fails the chain check with `key-log-invalid`, both at depth 0. Start at
depth 0 with the credential as `P`.

1. Verify the issuer JWT of `P`: `typ` MUST be `dc+sd-jwt`; `kid` (made absolute
   against `iss` if it starts with `#`) MUST be a DID URL of `iss`; verify the
   signature with the key the `iss` document lists under `assertionMethod` for
   that `kid`. Require `iss`, `sub`, integer `iat` and `exp`, an `evidence`
   array, `iat` at most 60 s in the future, and a member or organisation `vct`.
   An integer here is a JSON number without a fractional part whose magnitude
   is at most 2^53 − 1, so that every JSON parser reads the same value. A
   payload that is not RFC 8259 JSON (`NaN`, `Infinity`) is
   `malformed-credential`.
   If `P` is the trust anchor's own organisation credential with
   `evidence: []`, the chain ends successfully. Otherwise require exactly one
   evidence object `E`.
2. Decode `E.clientDataJSON` as UTF-8 JSON. Require `type` to be
   `webauthn.get`, `challenge` to equal `challenge(P, E)` (§4.2), and
   `crossOrigin` not to be `true`.
3. Resolve the trust anchor document and read its `HavenWebAuthnRelyingParty`
   service. Require the client data `origin` to be one of its `origins`.
4. Decode `E.authenticatorData`. Require at least 37 bytes, bytes 0 to 31 equal
   to SHA-256 of the UTF-8 `rpId`, and the flags byte 32 to have both user
   presence (`0x01`) and user verification (`0x04`) set. The signature counter
   is not checked; verification is stateless.
5. Find the approver's key.
   1. If `E.kind` is `approval` and `E.approverCredential` is absent, let `T`
      be `P.iat` (for an instruction, `issuedAt`) and look up
      `E.credentialId` in `keysAt(T)` of the key log (§4.5). The trust anchor
      document is not consulted.
      - If found, its `jwk` is the key. `E.approver` MUST equal
        `{ sub: <its sub>, memberOf: <ta>, role: "admin" }`, otherwise
        `approver-mismatch`. The approver is a trust anchor admin, reported as
        `{ sub, memberOf: <ta>, via: "trust-anchor" }`.
      - **Bootstrap rule**, the only self-approval. If not found, the key is
        the `jwk` of the entry of `P.authenticators` whose `credentialId`
        equals `E.credentialId` when all of these hold: `P` is a trust anchor
        admin member credential (`iss` the trust anchor, a member `vct`,
        `memberOf` resolving to the trust anchor, `role = admin`),
        `E.approver.sub = P.sub`, and `keysAt(T)` is empty. When `P` is a
        signed credential, `P.jti` MUST also be the `jti` of a `credential`
        entry of the log; the issuer's pre-signing check (below) skips this,
        since the issuer appends that entry when it signs. `E.approver` MUST
        then equal `{ sub: P.sub, memberOf: <ta>, role: "admin" }`, otherwise
        `approver-mismatch`. The rule admits the first trust anchor admin and
        a re-bootstrap after every admin key was lost, nothing else: while any
        admin key is active, self-approval fails.
      - Otherwise the step fails with `approver-key-not-found`. This covers a
        key that is in the log now but was added after `T`, and one removed
        before `T`.
   2. Otherwise `E.approverCredential` is required, even when the passkey is
      also a trust anchor admin passkey in the key log: the approver then acts
      for the organisation of their member credential. Verify it as in step 1 and
      call its payload `AC`. Require a member `vct` and
      `AC.iat <= P.iat <= AC.exp` (for an instruction, `issuedAt` in place of
      `P.iat`). The entry of `AC.authenticators` whose `credentialId` equals
      `E.credentialId` gives the key. `E.approver` MUST equal `AC.sub`, the
      organisation of `AC` and `AC.role`. The current revocation status of
      `AC` is deliberately not checked: a later revocation of the approver does
      not undo what they approved.
6. Verify the signature over `authenticatorData || SHA-256(clientDataJSON)`,
   both as raw bytes. For an EC P-256 key the WebAuthn signature is ASN.1 DER
   (convert it to `r || s` for WebCrypto; tolerate redundant leading zeros,
   reject trailing bytes). For an Ed25519 key the signature is raw. Any other
   key type fails.
7. Check authority. "Trust anchor admin" means step 5.1, or an `AC` whose
   organisation is the trust anchor and whose role is `admin`.
   - Organisation credential: `P.iss` MUST be the trust anchor DID and the
     approver a trust anchor admin. Endorsements are not allowed.
   - Member credential of organisation `org` (the first `memberOf` entry):
     `P.iss` MUST equal `org`. The approver MUST be an admin. When `org` is
     the trust anchor itself, only a trust anchor admin may approve.
     Otherwise the approver MUST be an admin whose organisation is `org`, or
     a trust anchor admin when `P.role` is `admin`. A trust anchor admin
     approving a `member` credential of another organisation fails with
     `approver-wrong-organisation`. The trust anchor seats an organisation's
     admins; the organisation's own admins approve its members. A verifier
     cannot tell a first admin from a later one, since the trust anchor
     issues the organisation credential and could reissue it, so limiting
     the trust anchor to the first admin is the issuer's policy.
   - Endorsement: the approver MUST come from step 5.2 with `AC.sub = P.sub`,
     the same organisation as `P` and `AC.role = P.role`. Compare the complete
     issuer-signed payloads of `AC` and `P`: only `authenticators`, `iat`, `jti`,
     and `evidence` MAY differ. These permit passkey updates and reissue
     metadata; every other claim MUST remain identical, including `exp`, `vct`,
     `cnf`, `credentialStatus`, disclosure hashes, and all membership entries.
     Added or removed claims outside this allowlist also fail with
     `endorsement-payload-mismatch`. Preserve disclosure salts when reissuing.
8. If step 5.2 was used, repeat from step 1 with `AC` as `P` at depth + 1. Fail
   when the depth would exceed 8. The chain succeeds when it ends in a trust
   anchor admin passkey of the key log (step 5.1).

The result is `{ ok: true, approvers }` with one entry
`{ sub, memberOf, via: "trust-anchor" | "credential" }` per level, nearest
first, or `{ ok: false, reason, depth }`. Chain verification does not check the
expiry or revocation of `P` itself.

For an **instruction**, run steps 2 to 6 against `challenge(instruction, E)`,
require `E.kind = approval` and `E.approver.sub = actor`, and verify the
approver credential's own chain from step 1. Which approvers may revoke which
credential is the caller's policy.

**Before signing**, an issuer runs the same checks on the unsigned payload
with `evidence: [E]` added (`verify_evidence_for_payload` /
`verifyEvidenceForPayload`), so that a signature always follows a human
decision that was already checked.

### 4.4 Failure reasons

Implementations report the first failing check with one of these reasons, so
results compare across runtimes:

| Step | Reasons |
|------|---------|
| 1 | `malformed-credential`, `unexpected-typ`, `unsupported-alg`, `did-resolution-failed`, `issuer-key-not-found`, `bad-issuer-signature`, `issued-in-future`, `unknown-vct`, `evidence-count`, `malformed-evidence`, `malformed-instruction` |
| 2 | `client-data-invalid`, `digest-mismatch`, `cross-origin` |
| 3 | `relying-party-missing`, `origin-not-allowed` |
| 4 | `authenticator-data-invalid`, `rp-id-hash-mismatch`, `user-not-present`, `user-not-verified` |
| 5 | `approver-credential-missing`, `approver-credential-not-member`, `approver-credential-out-of-window`, `approver-key-not-found`, `approver-mismatch` |
| 6 | `bad-webauthn-signature`, `unsupported-alg` |
| 7 | `approver-not-admin`, `approver-wrong-organisation`, `approver-not-trust-anchor`, `issuer-not-organisation`, `issuer-not-trust-anchor`, `endorsement-subject-mismatch`, `endorsement-payload-mismatch` |
| 8 | `depth-exceeded` |
| Key log (§4.5), before step 1 | `key-log-unavailable` (fetch or resolution failed), `key-log-invalid` (chain, signature or shape of the log) |

`depth` is 0 for the credential itself and *n* for the *n*-th approver
credential down the chain. Key log failures are reported at depth 0.

### 4.5 The trust anchor key log

The trust anchor key log is an append-only, hash-chained list of the events
that seat and unseat trust anchor admins. It answers which passkeys could
approve as a trust anchor admin at a given time, so the trust anchor DID
document, which only shows the present, never decides a past approval.

Each entry is

```json
{
  "seq": 1,
  "kind": "credential",
  "at": 1797408060,
  "prev": null,
  "hash": "<base64url, 32 bytes>",
  "material": { "kind": "credential", "jwt": "<issuer JWT>~" }
}
```

with `material` one of

| `kind` | `material` | Logged when |
|--------|------------|-------------|
| `credential` | `{ "kind": "credential", "jwt": "<issuer JWT>~" }` | the trust anchor issues a member credential of its own organisation to a trust anchor admin, or the successor of one (a demotion is its successor with `role: member`) |
| `revocation` | `{ "kind": "revocation", "instruction": { ... }, "evidence": { ... } }` | a trust anchor admin credential is revoked: the `haven:RevokeCredential` instruction (§3) and its evidence |
| `passkey_revoked` | `{ "kind": "passkey_revoked", "sub": "urn:uuid:...", "credentialId": "<rawId>" }` | one passkey of a trust anchor admin is removed |

`at` is the time the event took effect, in epoch seconds. `kind` repeats
`material.kind`; the two MUST agree.

**Chain check.** Any violation fails the whole verification with
`key-log-invalid`:

1. `seq` is 1-based and gap-free in array order. `prev` of entry 1 is `null`;
   `prev` of entry n+1 is the `hash` of entry n. Every `hash` recomputes as
   `base64url(SHA-256(UTF-8(JCS({ seq, kind, at, prev, material }))))`. `at` is
   non-decreasing.
2. A `credential` entry's `jwt` is an issuer JWT with one trailing `~`. It
   verifies as in §4.3 step 1 against the trust anchor's `assertionMethod`
   key named by its `kid`, and its payload has `iss` the trust anchor, a member
   `vct`, `memberOf` resolving to the trust anchor, `role`, `sub`, `jti`,
   integer `iat` and `exp`, and `authenticators`. The evidence of a logged
   credential is not chain-verified during replay: the log is the authority,
   and verifying it would recurse into the log.
3. A `revocation` entry carries `instruction` and `evidence`; only
   `instruction.credential` (the `jti` it revokes) is used. A
   `passkey_revoked` entry carries `sub` and `credentialId`.

**Replay.** The state is a map of trust anchor admins by `sub`, each
`{ jti, iat, exp, authenticators: credentialId -> jwk }`. Entries apply in
order and take effect at their `at`, inclusive:

- `credential` replaces the record of its `sub`; when its `role` is not
  `admin`, the record is removed instead.
- `revocation` removes the record whose `jti` equals `instruction.credential`;
  no effect when no current record has that `jti`.
- `passkey_revoked` removes `credentialId` from the record of `sub`; no effect
  when absent.

`keysAt(t)` applies every entry with `at <= t`, then drops the records whose
credential does not cover `t` (`iat <= t <= exp`). The result maps each
`credentialId` to `{ sub, jwk }`. A `credentialId` belongs to one admin; if two
records list the same one, the record from the later entry wins.

The issuer stamps `iat` when it prepares a credential and logs it when it
signs, so a credential entry's `at` is at or after its `iat`. Its key only
counts for approvals whose anchor time is at or after `at`.

**Compromise stance.** Approvals signed while a key was active stay valid. A
compromised key is answered by revoking what it approved through the
revocation registry, never by rewriting the log. A rewritten log fails the
chain check for every verifier that compares it with what it saw before.

Pinning the genesis entry (a verifier remembers the `hash` of entry 1 per
trust anchor, as it does for revocation snapshot heads) is future work.

## 5. Batch approval

An admin who approves twenty new members, or offboards a team, should not need
twenty passkey taps. A batch lets one assertion approve N payloads (credentials,
instructions, or both) while every credential stays verifiable on its own,
without the rest of the batch.

### 5.1 Construction

Let `L_i = SHA-256(UTF-8(JCS(p_i without evidence/proof)))` be the raw digest
bytes of payload `i`, in an order the issuer chooses.

- **Leaf**: `L_i` itself.
- **Node**: `H(left, right) = SHA-256(0x01 || left || right)`.
- **Tree**: level 0 is the leaves. Each next level hashes pairs
  `(2k, 2k+1)` left to right; a lone last node is **promoted unchanged**, never
  duplicated. The single node of the last level is the **root**.
- **Challenge**: the root. The approver's passkey signs it as the WebAuthn
  challenge.

A batch of one has root `L_0`, so its challenge is `digest(p_0)`: single-payload
evidence is exactly a batch of size 1, and every verifier that implements §5
also verifies §4 evidence unchanged.

### 5.2 The path and the fold

Each credential's evidence carries the shared assertion values and its own
`merklePath`: the sibling digests from its leaf up to the root, each
`{ "hash": "<base64url, 32 bytes>", "position": "left" | "right" }`, where
`position` is the side the sibling occupies. A level at which the node was
promoted contributes no element. No leaf index is carried.

```text
fold(leaf, path):
  acc = leaf
  for {hash, position} in path:
    acc = H(hash, acc) if position == "left" else H(acc, hash)
  return acc
```

A path MUST be an array of at most 32 elements, each with a 32-byte `hash` and
a `position` of `left` or `right`; anything else fails with
`malformed-evidence`. Verification otherwise proceeds exactly as in §4.3, with
`challenge(P, E) = fold(L_P, E.merklePath)` in step 2.

### 5.3 Security notes

- **Domain separation.** Leaves carry no prefix so that size-1 batches stay
  byte-identical to single-payload evidence. A leaf preimage is JCS JSON text,
  which always starts with `{` (`0x7B`); a node preimage is 65 bytes starting
  with `0x01`. No input is both, so a node cannot be passed off as a payload
  digest without a SHA-256 collision. Verifiers always recompute the leaf from
  a payload and never accept a bare digest.
- **No duplication.** Promoting the odd node instead of duplicating it closes
  CVE-2012-2459, where two different batches share a root.
- **Independence.** A credential's path reveals only sibling hashes. Payloads
  contain random identifiers (`jti`, CRSet entry ids, disclosure salts), so the
  hashes reveal nothing about the other members of the batch.
- **What the person sees.** The authenticator shows no payload, only the
  issuer's approval screen does; this holds for single approvals too. For a
  batch, that screen MUST list every payload in the batch and their number.
- **Authority is per payload.** One assertion proves one decision by one
  person, but step 7 runs for each credential separately. A batch cannot give
  an approver authority they do not have for any individual member. Each
  evidence object picks its approver form on its own (§4.3 step 5), so a
  person who is a trust anchor admin in the key log and an admin of another
  organisation can
  approve trust anchor items without `approverCredential` and that
  organisation's items with it, under one assertion.
- **Approver window.** `AC.iat <= P.iat <= AC.exp` is checked per credential,
  so all payloads of a batch should share the approval time as `iat`.

### 5.4 Issuer procedure

1. Prepare every payload, fixing disclosure salts (`build_sd_jwt_payload`).
2. Compute the challenge and paths (`build_batch` / `buildBatch`), show the
   approval screen, and request one WebAuthn assertion over the challenge.
3. For each payload, build the evidence with its path
   (`build_webauthn_evidence` / `buildWebAuthnEvidence`), check it with
   `verify_evidence_for_payload`, then add it as `evidence: [E]` and sign.

## 6. Test vectors

- `tests/fixtures/evidence/evidence-vectors.json`: DID documents, the trust
  anchor key log (`keyLogs`, a map from trust anchor DID to its entries),
  credentials and instructions with their expected results, covering single
  approvals, endorsements, revocation instructions, batches of 3 and 5, a
  mixed credential and instruction batch, key log replay (keys added, removed
  by `passkey_revoked`, demoted and revoked before and after `iat`, the
  bootstrap rule, self-approval while an admin is active, a passkey listed
  only in the DID document), broken logs (`prev`, `seq`, `hash`, `at`, a
  foreign credential, an unavailable log), and negative cases (tampered
  payloads and signatures, wrong approvers, origins and flags, malformed
  paths), with at least one case for every failure reason in §4.4. A case
  may carry its own `didDocuments`, `keyLogs` or `maxDepth`, which replace
  the shared documents, the top-level key log map and the default depth
  limit for that case. Both runtimes must return the same `ok`, `approvers`,
  `reason` and `depth` for every case.
- `tests/fixtures/evidence/merkle-vectors.json`: known answers for the tree,
  batch sizes 1 to 9.

Both files are written by `tests/fixtures/evidence/gen_evidence_vectors.py`.

## 7. Scope

Not covered here yet: presentation evidence (a passkey assertion carried in
the key binding JWT), the revocation snapshot chain, and pinning the genesis
entry of the trust anchor key log.

Verifiers that implement only §4 ignore `merklePath` and so reject batch
evidence with `digest-mismatch`, which fails safe.
