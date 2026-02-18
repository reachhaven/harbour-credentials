from harbour.jose.keys import (
    generate_ed25519_keypair,
    generate_p256_keypair,
    keypair_to_jwk,
    p256_keypair_to_jwk,
    p256_public_key_to_did_key,
    p256_public_key_to_jwk,
    p256_public_key_to_multibase,
    public_key_to_did_key,
    public_key_to_jwk,
    public_key_to_multibase,
)
from harbour.jose.kb_jwt import create_kb_jwt, verify_kb_jwt
from harbour.jose.sd_jwt import issue_sd_jwt_vc
from harbour.jose.sd_jwt_verifier import verify_sd_jwt_vc
from harbour.jose.signer import sign_vc, sign_vc_jose, sign_vp_jose
from harbour.jose.x509 import (
    cert_to_x5c,
    extract_public_key,
    generate_self_signed_cert,
    validate_x5c_chain,
    x5c_to_certs,
)
from harbour.jose.verifier import (
    VerificationError,
    verify_vc,
    verify_vc_jose,
    verify_vp_jose,
)

__all__ = [
    # P-256 (ES256) keys
    "generate_p256_keypair",
    "p256_keypair_to_jwk",
    "p256_public_key_to_jwk",
    "p256_public_key_to_multibase",
    "p256_public_key_to_did_key",
    # Ed25519 keys
    "generate_ed25519_keypair",
    "keypair_to_jwk",
    "public_key_to_jwk",
    "public_key_to_did_key",
    "public_key_to_multibase",
    # VC-JOSE-COSE signing/verification
    "sign_vc_jose",
    "sign_vp_jose",
    "verify_vc_jose",
    "verify_vp_jose",
    "VerificationError",
    # SD-JWT-VC
    "issue_sd_jwt_vc",
    "verify_sd_jwt_vc",
    # KB-JWT
    "create_kb_jwt",
    "verify_kb_jwt",
    # X.509
    "generate_self_signed_cert",
    "cert_to_x5c",
    "x5c_to_certs",
    "extract_public_key",
    "validate_x5c_chain",
    # Legacy (deprecated)
    "sign_vc",
    "verify_vc",
]
