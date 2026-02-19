# Python API Reference

This section documents the Python API for Harbour Credentials.

## Modules

| Module | Description |
|--------|-------------|
| [`harbour.keys`](keys.md) | Key generation and DID encoding |
| [`harbour.signer`](signer.md) | JWT signing |
| [`harbour.verifier`](verifier.md) | JWT verification |
| [`harbour.sd_jwt`](sd_jwt.md) | SD-JWT selective disclosure |
| [`harbour.kb_jwt`](kb_jwt.md) | Key Binding JWT |
| [`harbour.x509`](x509.md) | X.509 certificates |

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
)

# KB-JWT
from harbour.kb_jwt import (
    create_kb_jwt,
    verify_kb_jwt,
)

# X.509
from harbour.x509 import (
    generate_self_signed_cert,
    validate_x5c_chain,
    cert_to_x5c,
    x5c_to_cert,
)
```
