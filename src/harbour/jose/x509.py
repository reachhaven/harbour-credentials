"""X.509 certificate chain support for EUDI-compliant VC signing."""

import base64
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    SECP256R1,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from harbour.jose.keys import PrivateKey, PublicKeyType


def generate_self_signed_cert(
    private_key: PrivateKey,
    *,
    subject: str,
    days: int = 365,
) -> x509.Certificate:
    """Generate a self-signed X.509 certificate.

    Args:
        private_key: P-256 or Ed25519 private key.
        subject: Common Name for the certificate subject/issuer.
        days: Validity period in days.

    Returns:
        Self-signed X.509 certificate.
    """
    # Build subject = issuer (self-signed)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
    )

    # Choose hash algorithm based on key type
    if isinstance(private_key, Ed25519PrivateKey):
        # Ed25519 uses None for hash (algorithm is built-in)
        cert = builder.sign(private_key, algorithm=None)
    else:
        cert = builder.sign(private_key, algorithm=hashes.SHA256())

    return cert


def cert_to_x5c(cert_chain: list[x509.Certificate]) -> list[str]:
    """Convert a certificate chain to x5c format (base64 DER strings).

    Args:
        cert_chain: List of certificates, leaf first.

    Returns:
        List of base64-encoded DER certificates (for JOSE x5c header).
    """
    return [
        base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(
            "ascii"
        )
        for cert in cert_chain
    ]


def x5c_to_certs(x5c: list[str]) -> list[x509.Certificate]:
    """Parse an x5c header value back to certificate objects.

    Args:
        x5c: List of base64-encoded DER certificates.

    Returns:
        List of parsed X.509 certificate objects.
    """
    return [
        x509.load_der_x509_certificate(base64.b64decode(cert_b64))
        for cert_b64 in x5c
    ]


def extract_public_key(cert: x509.Certificate) -> PublicKeyType:
    """Extract the public key from an X.509 certificate.

    Args:
        cert: X.509 certificate.

    Returns:
        The public key (P-256 or Ed25519).
    """
    return cert.public_key()


def validate_x5c_chain(
    x5c: list[str],
    *,
    trust_anchor: x509.Certificate | None = None,
) -> bool:
    """Validate an x5c certificate chain.

    Performs basic chain validation:
    - Each certificate is signed by the next one in the chain
    - The last certificate is self-signed (or matches the trust anchor)
    - All certificates are within their validity period

    Args:
        x5c: List of base64-encoded DER certificates (leaf first).
        trust_anchor: Optional trusted root certificate to validate against.

    Returns:
        True if the chain is valid.

    Raises:
        ValueError: If the chain is invalid.
    """
    if not x5c:
        raise ValueError("Empty certificate chain")

    certs = x5c_to_certs(x5c)
    now = datetime.datetime.now(datetime.timezone.utc)

    for i, cert in enumerate(certs):
        # Check validity period
        if now < cert.not_valid_before_utc:
            raise ValueError(f"Certificate {i} is not yet valid")
        if now > cert.not_valid_after_utc:
            raise ValueError(f"Certificate {i} has expired")

    # Verify chain signatures: each cert should be signed by the next
    for i in range(len(certs) - 1):
        issuer_pub = certs[i + 1].public_key()
        try:
            _verify_cert_signature(certs[i], issuer_pub)
        except Exception as e:
            raise ValueError(
                f"Certificate {i} signature verification failed: {e}"
            ) from e

    # Verify the last cert (root)
    last = certs[-1]
    if trust_anchor is not None:
        # Verify against provided trust anchor
        try:
            _verify_cert_signature(last, trust_anchor.public_key())
        except Exception as e:
            raise ValueError(
                f"Root certificate does not match trust anchor: {e}"
            ) from e
    else:
        # Self-signed: verify against its own public key
        try:
            _verify_cert_signature(last, last.public_key())
        except Exception as e:
            raise ValueError(f"Root certificate is not self-signed: {e}") from e

    return True


def _verify_cert_signature(cert: x509.Certificate, issuer_public_key) -> None:
    """Verify a certificate's signature using the issuer's public key."""
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if isinstance(issuer_public_key, EllipticCurvePublicKey):
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ECDSA(cert.signature_hash_algorithm),
        )
    elif isinstance(issuer_public_key, Ed25519PublicKey):
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
        )
    else:
        raise TypeError(f"Unsupported key type: {type(issuer_public_key)}")
