# Harbour Batched Credential Evidence Specification

**Version**: 1.1.0-draft
**Status**: Draft
**Namespace**: `https://harbour.reachhaven.io/evidence/v1`

---

## 1. Overview

This document specifies **batched credential evidence**: a mechanism that lets an
authorizing party approve the issuance of many credentials with a **single
signature**, while keeping every issued credential **independently verifiable** —
each credential carries everything needed to check its own evidence section
without access to the rest of the batch.

All credentials in this specification are **`dc+sd-jwt`** (SD-JWT Verifiable
Credentials, [SD-JWT-VC]). No other credential format is in scope.

### 1.1 Motivating scenario

The Harbour Signing Service executes all credential proofs in a dataspace on the
issuers' behalf (ADR-006), and authorization flows up a trust chain (Trust Anchor
→ organization → employee). A common operation is an organization authorizing the
issuance of credentials for _all of its employees at once_. The authorizing admin
should sign **once**, not once per employee.

### 1.2 The two constraints in tension

| Constraint                      | Consequence                                                                |
| ------------------------------- | -------------------------------------------------------------------------- |
| **One signature**               | The authorizer signs a single commitment over the whole batch.             |
| **Self-contained verification** | Each issued credential must, on its own, prove that _it_ is covered by that one commitment. |

The resolution is a **cryptographic commitment with per-item inclusion proofs**:
the authorizer signs a single **Merkle root** over the batch, and each issued
credential carries a **Merkle inclusion proof** binding its own payload to that
root.

### 1.3 Why a Merkle tree

A flat list of signed leaf hashes would also satisfy both constraints, but every
credential would then have to carry all N hashes — `O(N)` overhead per
credential. A Merkle tree reduces the per-credential proof to `O(log N)` sibling
digests (14 digests for a batch of 10 000) at the cost of a small, fully specified
tree construction.

---

## 2. Trust Model

Issuers are **sovereign** (ADR-006). The `issuer` of every credential is the
vouching party's own `did:ethr`: the **Trust Anchor** issues LegalPerson
credentials (including its own — `issuer == credentialSubject.id`, the
self-signed-root shape), and each **organization** issues the NaturalPerson
credentials of its members (`memberOf == issuer`).

The **Signing Service** produces every credential proof, but never as itself:
its key is listed as an **assertion-only** verification method inside the
issuer's `did:ethr` document (an opt-in mandate via the `IdentityController`,
see `docs/did-identity-system.md`), and the proof's `kid` names that method in
the **issuer's** document. The issuer can revoke the mandate unilaterally at
any time by editing its DID document, so the Signing Service executes the
credential lifecycle without ever owning it.

Organizations and natural persons are thus sovereign over their identifiers,
their credentials, **and** disclosure (selective disclosure when presenting).
The separation of powers is between **human authorization and automated proof
execution**, not between two organizations:

- The **evidence** (this spec) is signed by a _human admin_ whose wallet key
  is authorized on the issuing organization's `did:ethr`. It is the actual
  authorization decision and a durable, non-repudiable record of who approved
  the issuance.
- The **proof** is produced by the Signing Service under the mandate above.
  It makes the credential verifiable; it decides nothing.

Because every verifier checks the evidence, a Signing Service that minted a
credential nobody authorized is detectable: it cannot forge an admin's
signature. Revocation follows issuance (§7): the revocation pointer lives in
the issuer's own DID document, while the Signing Service maintains the
revocation data as an operational service.

---

## 3. Roles

| Role           | Identity                                                                    | Action                                                                                                                            |
| -------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **Authorizer** | The issuing organization's `did:ethr`; the signature is made by a **human admin's key** authorized on that DID | Computes the Merkle root over the batch and signs **one** authorization JWT over that root with an admin key in the org's DID document. |
| **Issuer**     | The vouching party's `did:ethr` (Trust Anchor for LegalPerson credentials, the organization for NaturalPerson credentials — ADR-006) | Named in each credential's `issuer`. Its proofs are executed by the **Signing Service** under the assertion-only mandate key in the issuer's DID document. |
| **Signing Service** | Haven-operated proof executor | Assembles the batch, obtains the admin's single authorization signature, embeds each credential's inclusion proof, and signs each `dc+sd-jwt` proof with its mandate key. Maintains revocation data (§7). |
| **Verifier**   | Any relying party                                                           | Verifies one issued credential and its evidence in isolation.                                                                   |

Authorizer and issuer usually coincide at the DID level (the organization both
authorizes and issues); the real separation is between the **human admin** who
signs the evidence and the **automated Signing Service** that signs the proof.
The authorizer commits to the full content of each credential in the batch
(§4.1).

---

## 4. Cryptographic Construction

### 4.1 Leaf

The leaf for credential _i_ commits to the **issuer-signed SD-JWT payload** of
that credential, with the evidence section removed:

```text
leaf_payload_i = <issuer SD-JWT claims of credential_i>  without the "evidence" member
leaf_i         = SHA-256( 0x00 ‖ JCS(leaf_payload_i) )
```

Where:

- `JCS(·)` is the RFC 8785 JSON Canonicalization Scheme. It is deterministic, so
  the leaf bytes are reproducible by any party independent of formatting.
- `0x00` is the **leaf domain-separation prefix** ([RFC 6962] §2.1).
- The `evidence` member is removed because it is what _carries_ the inclusion
  proof; it cannot be part of what the proof commits to (otherwise the leaf would
  depend on itself). The authorizer commits to everything else, including the
  credential's `credentialStatus` entries (§7).

#### 4.1.1 Disclosure invariance

The leaf is computed over the **issuer-signed claims set** — the object that
contains the salted `_sd` digests ([SD-JWT] §4.2), **not** the plaintext of
selectively-disclosable claims. This gives a key property:

> The leaf is invariant under the issued credential's own selective disclosure.

A verifier who receives credential _i_ with some claims redacted still recomputes
the identical leaf, because the leaf hashes the `_sd` digests, not the cleartext.
A consequence for privacy: sibling digests in a Merkle proof are over salted
material and therefore leak no claim content (§9.4).

### 4.2 Internal nodes and tree shape

```text
node(L, R) = SHA-256( 0x01 ‖ L ‖ R )
```

- `0x01` is the **internal-node domain-separation prefix** ([RFC 6962] §2.1). The
  distinct `0x00` / `0x01` prefixes prevent an internal node from being presented
  as a leaf (a second-preimage class of attack).
- Leaves are ordered by their position in the batch; this order is fixed before
  hashing.
- A **lone (odd) node is promoted unchanged** to the next level — it is **not**
  duplicated. Last-node duplication is forbidden because it lets two distinct
  trees share a root (CVE-2012-2459).

The **Merkle root** is the single root node, encoded base64url without padding.

### 4.3 The single signature

The authorizer signs **one** compact JWS — the **authorization JWT** — over the
batch root. This is a plain ES256 JWS, **not** an SD-JWT KB-JWT: the authorizer
presents no credential, so there is nothing for a KB-JWT `sd_hash` to bind. Its
claims are:

| Claim   | Value                                                                          |
| ------- | ------------------------------------------------------------------------------ |
| `iss`   | The authorizer's `did:ethr`.                                                   |
| `aud`   | The credential `issuer`'s DID — the identity under which the batch will be issued (ADR-006). |
| `iat`   | Issued-at (Unix seconds). Used for historical key resolution (§6).             |
| `nonce` | The base64url Merkle root over the batch.                                      |

Header: `alg: ES256`, `typ: harbour-batch-auth+jwt`, and `kid` referencing the
verification method in the authorizer's DID document used to sign.

Carrying the commitment in `nonce` mirrors the established Harbour pattern, where
a `did:ethr` key signs an instruction "as the nonce inside a JWT" (the
`IdentityController` flow, `docs/did-identity-system.md`). The signing key is a
verification method of the authorizer's `did:ethr`, so any verifier can confirm
the signer's authority by **resolving the DID** — no embedded credential is
needed (§4.4).

> **Future direction.** The cleaner long-term binding is the OID4VP
> `transaction_data` mechanism ([OID4VP] §8.4), carrying the root in a dedicated
> `transaction_data` object bound via `transaction_data_hashes` and separating a
> replay nonce from the content commitment. No known deployed wallet currently
> supports `transaction_data`, so this version uses the `nonce` field and reserves
> migration for later.

### 4.4 Why no embedded credential

An earlier design embedded the authorizer's full `dc+sd-jwt` presentation in every
issued credential. Under the trust model of §2 this is unnecessary, and it is
dropped:

- **Verifiability** of the signature comes from resolving the authorizer's
  `did:ethr` and checking the signing key is one of its verification methods —
  not from an embedded `cnf` key.
- **Authority** to authorize is established by the Signing Service's act of
  issuing plus the on-chain trust graph (Trust Anchor endorses organizations),
  not by embedded credential claims.
- **Revocation** is handled by the dual status entries of §7, not by an embedded
  credential's status.

Dropping the embedded presentation also removes the recursion in which an
authorizer credential carries its own evidence containing further credentials, and
removes the `O(batch)` replication of a presentation across every issued
credential.

### 4.5 Issuance flow

1. The Signing Service assembles the batch of fully-formed credential payloads
   (each already carrying its `credentialStatus` entry, §7, validity, claims).
2. It computes each `leaf_i` (§4.1) and builds the tree (§4.2), yielding the root.
3. It sends the batch (or the root, if the authorizer reconstructs leaves
   independently) to the authorizer, who signs one authorization JWT with
   `nonce` = root (§4.3).
4. The Signing Service embeds `(authorizer, authorization, merkleProof)` into each
   credential's evidence (§5) and issues (envelopes / signs) each `dc+sd-jwt`.

> **No signature in the commitment.** Everything the authorizer signs is computed
> from **unsigned** canonical payloads, with no dependency on any envelope
> signature. Both the Merkle leaves (§4.1) and any `harbour.gx:digestSRI`
> references inside a payload are `sha256(JCS(unsigned credential document))` —
> the same RFC 8785 canonicalization, differing only in scope (a leaf excludes the
> `evidence` member). So steps 1–3 (resolve SRIs → compute leaves → build tree →
> single authorizer signature) all complete before any `dc+sd-jwt` is enveloped in
> step 4. This avoids a cycle that would otherwise arise if SRIs or leaves were
> taken over signed VCs: a VC's signature would then depend on a root that depends
> on that signature.

---

## 5. Wire Format

Each issued credential carries one evidence object of the
`harbour:BatchCredentialEvidence` ontology class (defined in
`linkml/harbour-core-credential.yaml`):

```jsonc
"evidence": [{
  "type": ["harbour:BatchCredentialEvidence"],

  // The authorizer's did:ethr. MUST equal the authorization JWT's `iss`.
  "authorizer": "did:ethr:...",

  // The ONE authorization JWT over the batch root (typ: harbour-batch-auth+jwt,
  // nonce = base64url Merkle root). Identical across all credentials in the batch.
  "authorization": "<compact JWS>",

  // This credential's inclusion proof against the root signed in `authorization`.
  "merkleProof": {
    "path": [
      { "hash": "<base64url-sha256>", "position": "left"  },
      { "hash": "<base64url-sha256>", "position": "right" }
    ]
  }
}]
```

- `authorizer` — the authorizing party's `did:ethr`, surfaced so the evidence is
  self-describing without decoding the JWT. MUST equal the JWT's `iss`.
- `authorization` — the single ES256 JWS (§4.3), byte-identical in every
  credential of the batch.
- `merkleProof.path` — the ordered sibling digests from the leaf up to the root.
  `position` states whether the sibling is the **left** or **right** input to
  `node(L, R)` at that level. A level at which the leaf's ancestor was promoted
  (no sibling, §4.2) has no entry. The path carries no leaf index: `position`
  alone fully determines the fold.

The Merkle root itself is **not** repeated in the evidence object — it is the
signed `nonce` inside `authorization`, and the verifier reads it from there
(§6, step 5).

---

## 6. Verification

A verifier holding **one** issued credential MUST:

1. **Verify the issued credential** — the SD-JWT proof over credential _i_,
   against the verification method its `kid` names in the **issuer's** DID
   document (in practice the Signing Service's assertion-only mandate key,
   §2).
2. **Recompute the leaf** — take the issued credential's issuer-signed claims set,
   remove the `evidence` member, apply `JCS`, prepend `0x00`, and SHA-256 →
   `leaf_i` (§4.1). Because the leaf is over `_sd` digests, this succeeds even if
   the credential is presented with claims redacted.
3. **Fold the proof** — combine `leaf_i` with each entry of `merkleProof.path`
   using `node(L, R)` and the stated `position` at each level → `computed_root`.
4. **Verify the authorization** — resolve the `authorizer` `did:ethr` **as of the
   authorization JWT's `iat`** (historical resolution — see below), find the
   verification method named by the JWT `kid`, and verify the ES256 signature.
   Check `iss` = `authorizer` and `aud` = the credential's `issuer`.
5. **Compare** — base64url-decode the JWT `nonce` and require it to equal
   `computed_root`. This proves, from this credential alone, that its payload was
   covered by the authorizer's single signature.
6. **Check status** — evaluate the `harbour:CRSetEntry` under §7: the
   credential is valid only if the entry resolves and does not report it
   revoked. The entry being unresolvable (the issuer's CRSet service deleted)
   fail-closes to revoked.

**Historical vs current resolution.** Step 4 resolves the authorizer DID _as of
`iat`_ (via `did:ethr` `versionTime`), so the authorization is an immutable
historical fact — "the organization authorized this at time T" — that later key
rotation cannot break. Step 6's status checks, by contrast, use the **current** DID
state and current cascade — "the organization still stands behind it now." Keep the
two separate: signing authority is historical; revocation is current.

---

## 7. Revocation

Revocation uses the existing Harbour **CRSet** mechanism — there is **no new
status type**. A credential carries **one `harbour:CRSetEntry`** whose
`statusServiceOperator` is the **issuer's DID** (ADR-006: revocation authority
follows issuance authority):

> **valid ⟺ the `CRSetEntry` resolves AND does not report the credential revoked**

An entry that cannot be resolved (its operator DID has no CRSet service) is
**fail-closed**, i.e. treated as revoked (§7.3). That the resolution path runs
through the issuer's own DID document is exactly what gives the issuer its
kill switch (§7.2).

### 7.1 The CRSet mechanism and its storage

The CRSet ([CRSet]) is a Bloom filter cascade with fixed-size padding and a
regular publishing schedule, giving metadata privacy: an observer cannot infer how
many credentials exist or how many are revoked. **This implementation diverges
from the paper's Ethereum-blob storage.** Instead:

- the cascade is published to **IPFS** and addressed by a stable **IPNS** name, so
  the link is permanent while the content updates on each republish;
- the identity/registry layer can therefore live on **any Ethereum L2** — because
  the revocation data is off-chain (IPFS), the choice of chain is decoupled from
  storage.

Resolution reuses the existing CRSet verifier:

```text
CRSetEntry.statusServiceOperator (a DID)
  → resolve DID document
  → find the harbour:CRSetRevocationRegistryService (by type)
  → service endpoint = an IPNS address
  → resolve IPNS → fetch the cascade from IPFS
  → membership-test statusIndex against the cascade
```

`statusIndex` is the credential's random 256-bit revocation ID. Checking is
**non-interactive for the holder** — the verifier fetches the cascade and runs the
test. The privacy properties (padding, scheduled republish) are unchanged from the
paper.

### 7.2 The entry: issuer-controlled pointer, Signing-Service-maintained data

`statusServiceOperator` is the **issuer's DID**. The issuer's DID document
carries a CRSet service entry that points to the IPNS of the revocation data
the **Signing Service maintains** as an operational service. The two halves of
revocation authority split along the same line as issuance itself (§2):

**Routine, per-credential revocation — Signing Service.** The batch's N
revocation IDs join the cascade the Signing Service maintains. It performs
routine revocation (key compromise, issuance error, a single employee leaving)
by adding the ID to the set; latency is bounded by the publish interval.

**Issuer-wide kill switch — issuer.** The resolution path depends on the
issuer's own DID service entry. To revoke **all** of its issued credentials at
once — or to sever the Signing Service entirely — the issuer **deletes or
redirects that CRSet service entry in its DID document** (for `did:ethr`, a
`revokeAttribute` authorized by its key via the `IdentityController` —
serverless, immediate, and impossible for the Signing Service to block). The
CRSet verifier then resolves the operator DID, finds no CRSet service, and
fail-closes → revoked for every credential the issuer backs.

This lever is deliberately **coarse**: it severs everything the issuer has
issued, not one employee. A per-employee variant is impossible without
leaking — distinct per-employee service entries would publish an on-chain
roster and make every firing a public event, defeating the CRSet's metadata
privacy. So the kill switch covers issuer-wide cases (ecosystem exit, key
compromise, dispute with the Signing Service) and **backstops** the routine
path: because the issuer always holds the pointer, the Signing Service can
never keep an issuer's credentials alive against its will. Note the converse
also holds by design: since the issuer owns the credential lifecycle
(ADR-006), an issuer that redirects its service entry to stale data can
resurrect credentials the Signing Service revoked — routine revocation is an
operational service the issuer delegates, not an authority held against the
issuer. Single-employee revocation driven by the organization is simply a
request to the Signing Service (honored by adding the ID to the cascade),
which is unproblematic because organization and issuer are the same party.

### 7.3 Verifier rules (normative)

1. **Fail-closed.** If an entry's operator DID resolves but exposes **no** CRSet
   service, the credential MUST be treated as **revoked**. (This inverts the usual
   "missing status mechanism = error" default; implementers and third-party
   verifiers MUST honor it, or the kill switch silently fails.)
2. **Inconclusive ≠ valid.** A transient resolution failure (DID resolution, IPNS,
   or IPFS unavailable) MUST NOT be treated as valid, nor as revoked; verification
   cannot complete until a finalized view is obtained. Only a confirmed, finalized
   _absence_ of the CRSet service counts as revoked.
3. **Dedicated entry.** In the issuer's DID document, the CRSet service used
   for this kill switch MUST serve no other purpose, so that deleting it does
   exactly one thing (no blast radius onto the issuer's other services).
4. **Toggle vs monotonicity.** Re-adding the issuer's CRSet service restores
   issuer-level liveness, and any credential whose `statusIndex` is in the
   cascade (§7.2) stays revoked for as long as the entry points at that
   cascade. Per-credential revocations are monotonic under an honest pointer;
   §7.2 notes the issuer's power to redirect it, which is intentional
   (revocation authority follows issuance authority).

---

## 8. Ontology

The following classes are defined in the Harbour core ontology
(`linkml/harbour-core-credential.yaml`). All slot ranges are named classes or
typed scalars — **never `range: Any`** — so the generated SHACL shapes stay
closed.

- **`harbour:BatchCredentialEvidence`** (subtype of `harbour:Evidence`) —
  `authorizer` (a DID, `range: uri`), `authorization` (the compact JWS string),
  and `merkleProof`.
- **`harbour:MerkleProof`** — `path` (ordered list of
  `harbour:MerklePathElement`).
- **`harbour:MerklePathElement`** — `hash` (base64url SHA-256 string) and
  `position` (enumeration: `left` | `right`).
- **`harbour:CRSetEntry`** (existing) — `statusServiceOperator`, `statusIndex`.
  A credential carries two of these (§7): one with the Signing Service as operator,
  one with the organization. No revocation-specific class is added by this spec.

`harbour:CredentialEvidence` is removed; `harbour:BatchCredentialEvidence` is the
sole credential-issuance evidence type (a batch of size 1 is a degenerate batch
with an empty `merkleProof.path`).

---

## 9. Security Considerations

### 9.1 Domain separation

Leaf and internal-node hashes use distinct `0x00` / `0x01` prefixes ([RFC 6962]).
Without this, an attacker could present an internal node as a leaf and forge an
inclusion proof for a value that was never authorized.

### 9.2 No duplicated nodes

Lone nodes are promoted, never duplicated, so two structurally different batches
cannot produce the same root (CVE-2012-2459). A verifier never needs the batch
size to validate a proof: forging a proof for an unauthorized leaf would require a
SHA-256 second preimage against the signed root.

### 9.3 Authorization is historical, revocation is current

The authorization signature is verified against the authorizer's verification
method **as of `iat`** (§6), so it remains valid — as an accountability record —
even after the organization rotates keys. Revocation liveness (§7.2) is evaluated
against **current** on-chain state. Conflating the two would let key rotation
either void past authorizations or silently un-revoke credentials.

### 9.4 Privacy

- The authorization reveals only the authorizer's public `did:ethr` — no PII, and
  no embedded credential.
- A Merkle proof reveals sibling **digests** but not their preimages, and the
  leaves hash salted `_sd` digests (§4.1.1), so an observer of one credential
  cannot learn — or guess-and-confirm — the content of sibling credentials.
- The CRSet (§7.1) hides per-credential revocation status and aggregate counts;
  the IPFS-stored cascade keeps the same padding/schedule privacy as the paper.
- The kill switch (§7.2) is an organization-wide action on the organization's own
  DID document; it reveals only that the organization withdrew its CRSet service,
  never per-employee information.

### 9.5 Fail-open hazard

The fail-closed rule (an unresolvable CRSet service ⇒ revoked, §7.3) is the
opposite of the usual fail-open default. A verifier that treats a missing CRSet
service as "valid" silently defeats the organization's sovereign revocation lever.
The rule is therefore normative for all CRSet entries, not a special case.

### 9.6 Nonce as commitment

The authorization JWT's `nonce` carries the Merkle root rather than a random
replay nonce. Replay resistance rests on `aud` (binding to the Signing Service),
`iat`, and the content-uniqueness of the root. This is the same property as the
existing `IdentityController` instruction-binding pattern.

---

## 10. Test Vectors

The canonical vectors live in `tests/fixtures/batched-evidence-vectors.json`,
generated deterministically by `tests/fixtures/gen_batched_evidence_vectors.py`
and pinned by `tests/python/harbour/test_merkle.py` (so they cannot drift from the
implementation in `harbour.merkle`). They cover:

- **N = 4 batch** — four credential payloads, their four leaves, the two
  level-1 internal nodes and the root, and the four inclusion proofs. The root
  (which is the authorization JWT `nonce`) is
  `Uz_rIhlrkBdIgpN1mzZe_NlIU6fBJl7gHGLbN31wvKw`.
- **N = 1 degenerate batch** — root equals the lone leaf
  (`cHFmId-ZVri1SnhE3LkJyJ414pgmZg7sBFzCy-Db0No`), `merkleProof.path` is empty.
- **Evidence invariance (§4.1)** — the leaf is byte-identical whether or not the
  credential carries an `evidence` member (and a `proof` member). For a
  `dc+sd-jwt` credential this extends to selective disclosure, since the leaf is
  over the issuer payload's salted `_sd` digests (§4.1.1).
- **Negative vectors** — a tampered leaf, a swapped proof `position`, and a wrong
  root all fail to verify. (A duplicated-node forgery is structurally impossible:
  lone nodes are promoted, not duplicated, §9.2.)

Still to be added when the pipeline lands: an authorization-JWT vector (a real
ES256 JWS whose `nonce` is the N = 4 root, verified against a fixture key) and
status-resolution vectors (CRSet revoked; org CRSet service removed → fail-closed;
inconclusive ≠ valid, §7.3).

---

## 11. References

| Tag        | Document                                                                 | Local copy                          |
| ---------- | ------------------------------------------------------------------------ | ----------------------------------- |
| [VCDM2]    | W3C VC Data Model 2.0 — §5.6 evidence, §4.10 status                       | `references/vc-data-model-2.0.md`   |
| [SD-JWT]   | RFC 9901 — §4.2 salted disclosures, §4.3 Key Binding JWT                  | `references/sd-jwt-rfc9901.md`      |
| [SD-JWT-VC]| SD-JWT VC — `dc+sd-jwt`, `cnf`                                            | `references/sd-jwt-vc.md`           |
| [OID4VP]   | OpenID4VP 1.0 — §8.4 transaction_data (future direction)                  | `references/oid4vp-1.0.md`          |
| [did:ethr] | did:ethr Method Specification — services, attributes, version resolution | `references/did-ethr-method-spec.md`|
| [CRSet]    | Hoops, Gebele, Matthes — _CRSet: Private Non-Interactive VC Revocation_   | arXiv:2501.17089                    |
| RFC 8785   | JSON Canonicalization Scheme (JCS)                                        | —                                   |
| [RFC 6962] | Certificate Transparency — Merkle leaf/node domain separation            | —                                   |
| [IPFS]     | InterPlanetary File System — content-addressed cascade storage           | —                                   |
| [IPNS]     | InterPlanetary Naming System — stable mutable pointer to the cascade      | —                                   |
| —          | Harbour DID Identity System (`IdentityController`, P-256 on-chain)        | `docs/did-identity-system.md`       |

---

## 12. Version History

| Version     | Date       | Changes                                                                                       |
| ----------- | ---------- | --------------------------------------------------------------------------------------------- |
| 1.1.0-draft | 2026-07-06 | Sovereign-issuer trust model (ADR-006): issuer = vouching party's `did:ethr`, Signing Service signs under an assertion-only mandate key in the issuer's DID document; evidence signed by a human admin key on the org DID; single issuer-operated `CRSetEntry` replaces the dual-entry model; authorization JWT `aud` = credential issuer. |
| 1.0.0-draft | 2026-06-22 | Initial draft: Merkle-batched `BatchCredentialEvidence` for `dc+sd-jwt`; Model B trust model; DID-resolved authorization JWT; dual-entry revocation (CRSet + org-wide did:ethr kill switch). |
