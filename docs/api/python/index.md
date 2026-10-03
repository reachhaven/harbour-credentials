# Python API Reference

This section documents the Python API for Harbour Credentials.

## Modules

| Module | Description |
|--------|-------------|
| `harbour.keys` | Key generation and DID encoding |
| `harbour.signer` | JWT signing |
| `harbour.verifier` | JWT verification |
| `harbour.sd_jwt` | SD-JWT selective disclosure |
| `harbour.kb_jwt` | Key Binding JWT |
| `harbour.sd_jwt_vp` | SD-JWT Verifiable Presentations for privacy-preserving consent |
| `harbour.delegation` | Delegation challenge encoding and transaction data |
| `harbour.x509` | X.509 certificates |
| `harbour.evidence` | Passkey evidence chains ([spec](../../specs/passkey-evidence.md)) |
| `harbour.merkle` | Merkle batches: one passkey assertion approving many payloads |

## Quick Import Reference

```python
# Key management
from harbour.keys import (
    generate_p256_keypair,
    generate_ed25519_keypair,
    p256_public_key_to_did_key,
    public_key_to_did_key,
    private_key_to_jwk,
    public_key_to_jwk,
)

# Signing
from harbour.signer import (
    sign_vc_jose,
    sign_vp_jose,
)

# Verification
from harbour.verifier import (
    verify_vc_jose,
    verify_vp_jose,
    VerificationError,
)

# SD-JWT
from harbour.sd_jwt import (
    issue_sd_jwt_vc,
    verify_sd_jwt_vc,
    build_sd_jwt_payload,  # fix salts, return (payload, disclosures)
    sign_sd_jwt,           # sign a prepared payload
)

# KB-JWT
from harbour.kb_jwt import (
    create_kb_jwt,
    verify_kb_jwt,
)

# SD-JWT VP
from harbour.sd_jwt_vp import (
    issue_sd_jwt_vp,
    verify_sd_jwt_vp,
)

# Delegation
from harbour.delegation import (
    TransactionData,
    create_delegation_challenge,
    parse_delegation_challenge,
    verify_challenge,
)

# X.509
from harbour.x509 import (
    generate_self_signed_cert,
    validate_x5c_chain,
    cert_to_x5c,
    x5c_to_cert,
)

# Passkey evidence (docs/specs/passkey-evidence.md)
from harbour.evidence import (
    payload_digest,
    build_webauthn_evidence,
    static_resolver,
    verify_evidence_chain,
    verify_evidence_for_payload,
    verify_instruction_evidence,
)
from harbour.merkle import build_batch  # one challenge + a merklePath per payload
```
