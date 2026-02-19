"""Harbour - JOSE signing and verification for Verifiable Credentials.

This package provides cryptographic operations for W3C Verifiable Credentials:
- Key generation and management (Ed25519, P-256)
- VC/VP signing (VC-JOSE-COSE compact JWS)
- VC/VP verification
- SD-JWT-VC selective disclosure credentials
- Key Binding JWT for holder binding
- X.509 certificate support

Usage:
    from harbour import keys, signer, verifier
    from harbour.sd_jwt import issue_sd_jwt_vc, verify_sd_jwt_vc
"""


# Use lazy imports to avoid RuntimeWarning when running modules directly
def __getattr__(name):
    """Lazy import to avoid import cycle when running modules directly."""
    if name in (
        "PrivateKey",
        "PublicKeyType",
        "generate_ed25519_keypair",
        "generate_p256_keypair",
        "keypair_to_jwk",
        "p256_keypair_to_jwk",
        "public_key_to_did_key",
        "public_key_to_multibase",
    ):
        from harbour import keys

        return getattr(keys, name)
    elif name in ("sign_vc_jose", "sign_vp_jose"):
        from harbour import signer

        return getattr(signer, name)
    elif name in ("verify_vc_jose", "verify_vp_jose", "VerificationError"):
        from harbour import verifier

        return getattr(verifier, name)
    raise AttributeError(f"module 'harbour' has no attribute {name!r}")


__all__ = [
    # Keys
    "PrivateKey",
    "PublicKeyType",
    "generate_ed25519_keypair",
    "generate_p256_keypair",
    "keypair_to_jwk",
    "p256_keypair_to_jwk",
    "public_key_to_did_key",
    "public_key_to_multibase",
    # Signer
    "sign_vc_jose",
    "sign_vp_jose",
    # Verifier
    "verify_vc_jose",
    "verify_vp_jose",
    "VerificationError",
]
