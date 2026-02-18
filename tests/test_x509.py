"""Tests for X.509 certificate chain support."""

import datetime

import pytest
from cryptography import x509

from harbour.jose.keys import generate_ed25519_keypair, generate_p256_keypair
from harbour.jose.x509 import (
    cert_to_x5c,
    extract_public_key,
    generate_self_signed_cert,
    validate_x5c_chain,
    x5c_to_certs,
)


class TestSelfSignedCert:
    def test_generate_p256(self):
        priv, pub = generate_p256_keypair()
        cert = generate_self_signed_cert(priv, subject="Test CA")
        assert cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0].value == "Test CA"

    def test_generate_ed25519(self):
        priv, pub = generate_ed25519_keypair()
        cert = generate_self_signed_cert(priv, subject="Ed25519 CA")
        assert cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0].value == "Ed25519 CA"

    def test_validity_period(self):
        priv, _ = generate_p256_keypair()
        cert = generate_self_signed_cert(priv, subject="Test", days=30)
        now = datetime.datetime.now(datetime.timezone.utc)
        assert cert.not_valid_before_utc <= now
        delta = cert.not_valid_after_utc - now
        assert 29 <= delta.days <= 30


class TestX5cConversion:
    def test_cert_to_x5c_roundtrip(self):
        priv, _ = generate_p256_keypair()
        cert = generate_self_signed_cert(priv, subject="Test")
        x5c = cert_to_x5c([cert])
        assert len(x5c) == 1
        assert isinstance(x5c[0], str)

        # Roundtrip
        certs = x5c_to_certs(x5c)
        assert len(certs) == 1
        assert certs[0].subject == cert.subject

    def test_extract_public_key(self):
        priv, pub = generate_p256_keypair()
        cert = generate_self_signed_cert(priv, subject="Test")
        extracted = extract_public_key(cert)
        # Compare public numbers
        assert extracted.public_numbers() == pub.public_numbers()


class TestX5cValidation:
    def test_valid_self_signed(self):
        priv, _ = generate_p256_keypair()
        cert = generate_self_signed_cert(priv, subject="Root CA")
        x5c = cert_to_x5c([cert])
        assert validate_x5c_chain(x5c) is True

    def test_valid_with_trust_anchor(self):
        priv, _ = generate_p256_keypair()
        cert = generate_self_signed_cert(priv, subject="Root CA")
        x5c = cert_to_x5c([cert])
        assert validate_x5c_chain(x5c, trust_anchor=cert) is True

    def test_wrong_trust_anchor(self):
        priv1, _ = generate_p256_keypair()
        priv2, _ = generate_p256_keypair()
        cert1 = generate_self_signed_cert(priv1, subject="CA 1")
        cert2 = generate_self_signed_cert(priv2, subject="CA 2")
        x5c = cert_to_x5c([cert1])
        with pytest.raises(ValueError, match="trust anchor"):
            validate_x5c_chain(x5c, trust_anchor=cert2)

    def test_empty_chain(self):
        with pytest.raises(ValueError, match="Empty"):
            validate_x5c_chain([])

    def test_ed25519_self_signed(self):
        priv, _ = generate_ed25519_keypair()
        cert = generate_self_signed_cert(priv, subject="Ed25519 Root")
        x5c = cert_to_x5c([cert])
        assert validate_x5c_chain(x5c) is True


class TestSignWithX5c:
    """Integration: sign a VC-JOSE-COSE with x5c header, verify using cert."""

    def test_sign_verify_via_x5c(self):
        from harbour.jose.signer import sign_vc_jose
        from harbour.jose.verifier import verify_vc_jose

        priv, _ = generate_p256_keypair()
        cert = generate_self_signed_cert(priv, subject="Issuer")
        x5c = cert_to_x5c([cert])

        vc = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": {"id": "did:web:example.com"},
            "credentialSubject": {"id": "did:web:holder.example.com"},
        }

        token = sign_vc_jose(vc, priv, x5c=x5c)

        # Extract public key from x5c for verification
        certs = x5c_to_certs(x5c)
        pub = extract_public_key(certs[0])
        result = verify_vc_jose(token, pub)
        assert result["issuer"]["id"] == "did:web:example.com"
