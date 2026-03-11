# Gaia-X Domain Credentials

This directory contains the **complete Gaia-X credential storyline** — the
end-to-end user journey from trust anchor through organization and employee
onboarding to delegated blockchain transactions.

## Structure

Credentials use the `harbour_gx:` namespace prefix
(`https://w3id.org/reachhaven/harbour/gaiax-domain/v1/`) for domain types
and properties, while core envelope types use `harbour:`.

| File | Step | Description |
|------|------|-------------|
| `trust-anchor-credential.json` | — | Trust Anchor self-signed credential (root of trust) |
| `legal-person-credential.json` | 1 | Organization credential with registration data |
| `natural-person-credential.json` | 2 | Employee credential with identity and `memberOf` link |
| `delegated-signing-receipt.json` | 3+4 | Transaction receipt with embedded consent VP as evidence |

## Context Stack

All credentials use a stacked `@context` array:

```json
"@context": [
  "https://www.w3.org/ns/credentials/v2",
  "https://w3id.org/gaia-x/development#",
  "https://w3id.org/reachhaven/harbour/credentials/v1/",
  "https://w3id.org/reachhaven/harbour/gaiax-domain/v1/"
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
