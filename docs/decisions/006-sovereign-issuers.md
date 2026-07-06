# ADR-006: Sovereign Issuers with a Signing-Service Mandate

## Status

**Status:** Accepted

Supersedes the "Signing Service as sole issuer / dataspace-branded credentials"
trust model previously stated in `docs/specs/batched-credential-evidence.md` §2.

## Context

Two competing trust models had grown side by side:

1. **Signing Service as sole issuer.** Every credential's `issuer` is the
   Signing Service's own `did:ethr`; credentials are "dataspace-branded".
   This is what the examples, the story pipeline, and the batched-evidence
   spec §2 implemented.
2. **Sovereign issuers.** The `issuer` of a credential is the vouching
   party's own `did:ethr` — the Trust Anchor for a LegalPersonVC, the
   organization for a NaturalPersonVC — and the Signing Service merely
   *executes* proofs on the issuer's behalf under a revocable mandate.

The divergence produced concrete defects:

- A NaturalPersonVC whose `memberOf` (the organization) differed from its
  `issuer` (the Signing Service), leaving verifiers no simple
  `memberOf == issuer` check.
- A trust-anchor credential that could not satisfy the evidence chain: with
  the Signing Service as sole issuer, the root's credential needs an
  authorizer "above the root", which does not exist.
- Organizations were sovereign over their *identifiers* but not over the
  credentials that describe them, undermining the ecosystem's sovereignty
  guarantees (an issuer mandate that cannot be revoked is not a mandate).

Model 2 is the governing design (Haven design notes, July 2026). This ADR
ratifies it for this repository.

## Decision

### 1. The issuer is the vouching party's own `did:ethr`

| Credential | `issuer` | `credentialSubject.id` |
|---|---|---|
| LegalPersonVC (org) | Trust Anchor DID | organization DID |
| LegalPersonVC (Trust Anchor's own) | Trust Anchor DID | Trust Anchor DID |
| NaturalPersonVC | organization DID | natural person DID |

- The Trust Anchor holds a **normal LegalPersonVC** with `issuer ==
  credentialSubject.id` — the self-signed-root shape familiar from CA
  certificates. It is authorized (evidence) and proof-signed exactly like
  any other LegalPersonVC; trust in it comes from out-of-band knowledge of
  the Trust Anchor's DID, not from the signature chain.
- A NaturalPersonVC's `memberOf` MUST equal its `issuer`. This restores the
  one-line verification rule.

### 2. The Signing Service signs under a mandate, never as itself

The Signing Service produces every credential proof, but its key acts as a
verification method **inside the issuer's own `did:ethr` document**:

- The issuer opts in via the IdentityController; the Signing Service's
  P-256 key is written into the issuer's DID document as an
  **assertion-only** verification method (`#delegate-N`). It can produce
  credential proofs for that issuer and nothing else — it cannot edit the
  DID document or authenticate as the issuer.
- The proof JWT's `kid` is the **full DID URL of that verification method
  in the issuer's document** (e.g. `did:ethr:…:0xORG#delegate-1`), resolved
  at signing time. Verifiers resolve the issuer's DID document and verify
  against exactly that method.
- The issuer can revoke the mandate unilaterally at any time by editing its
  DID document. Haven operates the Signing Service but can never become an
  unavoidable intermediary.

### 3. Evidence is a human authorization

The `harbour:BatchCredentialEvidence` authorization JWT is signed by a
**human admin's key that is authorized on the issuing organization's
`did:ethr`** (the IdentityController maps 1..n admin wallet keys to the org
DID). The evidence `authorizer` is the organization's DID; the JWT `kid`
names the admin's verification method within it. In the repository examples
the org's `#controller` key stands in for "an org admin's wallet key".

Authorizer and issuer therefore usually coincide at the DID level (the org
authorizes and issues; a human admin signs the evidence, the Signing
Service signs the proof) — the separation of powers is between *human
authorization* and *automated proof execution*, not between two
organizations.

### 4. Credentials are independent; LegalPersonVCs are published

- A LegalPersonVC is never embedded inside a NaturalPersonVC. Holders
  present only their own credentials; the verifier resolves the
  organization's LegalPersonVC from its published location.
- The org's DID document carries a `harbour:LinkedCredentialService` entry
  pointing at the published LegalPersonVC (HTTPS). The host only needs to
  be available, not trusted — any copy verifies identically.
- Self-containment of an org's **own** Gaia-X compliance VCs inside its
  **own** LegalPersonVC (`harbour.gx:embeddedCredential`) remains allowed;
  it duplicates no cross-credential trust path.

### 5. Revocation: one entry, issuer-controlled pointer, SS-maintained data

A credential carries **one** `harbour:CRSetEntry` with
`statusServiceOperator` = the **issuer** DID. Resolution goes through the
issuer's DID document (`harbour:CRSetRevocationRegistryService`) to the
CRSet data the Signing Service maintains.

This keeps both functions of the previous two-entry design with less
machinery:

- **Routine revocation** — the Signing Service maintains the cascade data
  and adds revocation IDs as needed.
- **Kill switch** — the issuer deletes or redirects the service entry in
  its own DID document; verifiers fail closed (absent CRSet service ⇒
  revoked). Since the pointer lives in the issuer's document, revocation
  authority follows issuance authority.

## Consequences

- `examples/` and the story pipelines (Python + TypeScript) are re-cut:
  issuers per §1, single status entry per §5, DID documents gain the
  mandate verification method and service entries per §2/§4.
- The trust-anchor credential's evidence deadlock dissolves: the TA's LPVC
  and the org LPVCs share issuer (TA DID) and authorizer (TA DID), forming
  one coherent batch.
- `docs/specs/batched-credential-evidence.md` §2 (trust model), §3 (roles)
  and §7 (revocation) are rewritten to match; the "sole issuer /
  dataspace-branded" wording is withdrawn.
- Verifiers MUST check `memberOf == issuer` on NaturalPersonVCs.
- The Signing Service's own DID appears as `issuer` only on artifacts it
  genuinely issues for itself (e.g. delegated-signing receipts).

## References

- Haven design notes: "Haven Credentials" (internal, July 2026) — trust
  path, mandate, publication, and revocation rationale.
- `docs/specs/batched-credential-evidence.md` — evidence mechanism.
- `docs/did-identity-system.md` — IdentityController and `did:ethr` setup.
- ADR-005 — did:ethr migration.
