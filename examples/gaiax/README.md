# Gaia-X Domain Extensions

This directory contains **Gaia-X domain extensions** of the harbour credential
skeletons in the parent `examples/` directory. Each file adds Gaia-X compliance
data to the base harbour skeleton using the **composition pattern**.

## Composition Pattern

Harbour credentials use a two-layer model:

1. **Outer node** (`harbour:LegalPerson` / `harbour:NaturalPerson`) — harbour-owned
   properties (`name`, `memberOf`, CRSet status).
2. **Inner node** (`gxParticipant`) — a Gaia-X typed blank node
   (`gx:LegalPerson`, `gx:Participant`) carrying Gaia-X properties
   (`gx:registrationNumber`, `gx:headquartersAddress`, etc.).

This keeps harbour and Gaia-X SHACL shapes validating independently. The
`gxParticipant` slot is defined as `required: false` in the harbour schema — it
is only populated when Gaia-X compliance is needed.

## Skeleton to Extension Derivation

| Skeleton (parent `examples/`) | Gaia-X extension (this directory) | What's added |
|-------------------------------|-----------------------------------|--------------|
| `legal-person-credential.json` | `legal-person-credential.json` | `gxParticipant` with `gx:LegalPerson`, registration number, addresses |
| `natural-person-credential.json` | `natural-person-credential.json` | `gxParticipant` with `gx:Participant` |

The `@context` array in Gaia-X extensions includes the Gaia-X namespace:

```json
"@context": [
  "https://www.w3.org/ns/credentials/v2",
  "https://w3id.org/gaia-x/development#",
  "https://w3id.org/reachhaven/harbour/credentials/v1/"
]
```

Base skeletons omit this context entry entirely.

## Regenerating Signed Artifacts

```bash
source .venv/bin/activate
PYTHONPATH=src/python:$PYTHONPATH python -m credentials.example_signer examples/
```

This processes both `examples/*.json` and `examples/gaiax/*.json`, producing
signed artifacts in `examples/signed/` and `examples/gaiax/signed/` respectively.
