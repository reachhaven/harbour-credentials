# Gaia-X Domain Credentials

This directory contains the **complete Gaia-X credential storyline** — the
end-to-end user journey from trust anchor through organization and employee
onboarding to delegated blockchain transactions.

## Architecture

**`harbour.gx:LegalPersonCredential` IS the compliance credential.**

Holding a valid one means Haven has verified all three underlying Gaia-X VCs:

1. ✅ `gx:LegalPerson` — entity identity verified
2. ✅ `gx:VatID` — registration number notary-checked
3. ✅ `gx:Issuer` — T&C accepted

The three input VCs are **plain Gaia-X** (no harbour envelope type). The
`LegalPersonCredential` is the **compliance output** — Haven's stamp.

The `harbour.gx:LegalPerson` SHACL shape enforces all three VC references
via `sh:minCount 1` — machine-readable enforcement that the Gaia-X Loire
specification is missing.

## Structure

Credentials use the `harbour.gx:` namespace prefix
(`https://w3id.org/reachhaven/harbour/gx/v1/`) for domain types
and properties, while core envelope types use `harbour:`.

### Input VCs (plain Gaia-X, no harbour envelope)

| File | Issuer | Description |
|------|--------|-------------|
| `gx-legal-person.json` | Company (self-signed) | gx:LegalPerson self-description with name, addresses |
| `gx-registration-number.json` | Haven (notary) | gx:VatID with notary verification evidence |
| `gx-terms-and-conditions.json` | Company (self-signed) | gx:Issuer with T&C acceptance hash |

### Output VCs (harbour compliance credentials)

| File | Issuer | Description |
|------|--------|-------------|
| `legal-person-credential.json` | Haven (compliance) | Referenced pattern — compliance refs with digest hashes |
| `legal-person-credential-embedded.json` | Haven (compliance) | Embedded pattern — full gx VCs nested inline |

### Other Credentials

| File | Step | Description |
|------|------|-------------|
| `trust-anchor-credential.json` | — | Trust Anchor self-signed credential (root of trust) |
| `participant-vp.json` | — | VP bundling all 4 VCs (3 plain gx + 1 compliance) |
| `natural-person-credential.json` | 5 | Employee credential with identity and `memberOf` link |
| `delegated-signing-receipt.json` | 6+7 | Transaction receipt with embedded consent VP as evidence |

## Context Stack

All credentials use a stacked `@context` array:

```json
"@context": [
  "https://www.w3.org/ns/credentials/v2",
  "https://w3id.org/gaia-x/development#",
  "https://w3id.org/reachhaven/harbour/core/v1/",
  "https://w3id.org/reachhaven/harbour/gx/v1/"
]
```

## Regenerating Signed Artifacts

```bash
source .venv/bin/activate
PYTHONPATH=src/python:$PYTHONPATH python -m credentials.example_signer examples/
```

This processes both `examples/*.json` and `examples/gaiax/*.json`, producing
signed artifacts in `examples/signed/` and `examples/gaiax/signed/` respectively.

See the parent [`examples/README.md`](../README.md) for the full user journey
with sequence diagrams.
