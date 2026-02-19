"""Tests for KB-JWT creation and verification with transaction_data support."""

import pytest
from harbour.kb_jwt import create_kb_jwt, verify_kb_jwt
from harbour.keys import generate_p256_keypair, p256_public_key_to_jwk
from harbour.sd_jwt import issue_sd_jwt_vc
from harbour.verifier import VerificationError

SAMPLE_CLAIMS = {
    "iss": "did:web:did.ascs.digital:participants:ascs",
    "legalName": "Bayerische Motoren Werke AG",
    "email": "imprint@bmw.com",
}

VCT = "https://w3id.org/ascs-ev/simpulse-id/credentials/v1/ParticipantCredential"


@pytest.fixture()
def sd_jwt_with_cnf(p256_private_key, p256_public_key):
    """Issue an SD-JWT-VC with holder key binding (cnf)."""
    holder_pub_jwk = p256_public_key_to_jwk(p256_public_key)
    return issue_sd_jwt_vc(
        SAMPLE_CLAIMS,
        p256_private_key,
        vct=VCT,
        cnf={"jwk": holder_pub_jwk},
    )


class TestKBJWT:
    def test_create_appends_kb_jwt(self, sd_jwt_with_cnf, p256_private_key):
        result = create_kb_jwt(
            sd_jwt_with_cnf,
            p256_private_key,
            nonce="verifier-nonce-123",
            audience="https://verifier.example.com",
        )
        parts = result.split("~")
        # Last part should be the KB-JWT (not empty)
        assert len(parts[-1].split(".")) == 3

    def test_verify_kb_jwt_valid(
        self, sd_jwt_with_cnf, p256_private_key, p256_public_key
    ):
        sd_jwt_kb = create_kb_jwt(
            sd_jwt_with_cnf,
            p256_private_key,
            nonce="verifier-nonce",
            audience="https://verifier.example.com",
        )
        payload = verify_kb_jwt(
            sd_jwt_kb,
            p256_public_key,
            expected_nonce="verifier-nonce",
            expected_audience="https://verifier.example.com",
        )
        assert payload["nonce"] == "verifier-nonce"
        assert payload["aud"] == "https://verifier.example.com"
        assert "sd_hash" in payload
        assert "iat" in payload

    def test_verify_kb_jwt_wrong_nonce(
        self, sd_jwt_with_cnf, p256_private_key, p256_public_key
    ):
        sd_jwt_kb = create_kb_jwt(
            sd_jwt_with_cnf,
            p256_private_key,
            nonce="real-nonce",
            audience="https://verifier.example.com",
        )
        with pytest.raises(VerificationError, match="Nonce mismatch"):
            verify_kb_jwt(
                sd_jwt_kb,
                p256_public_key,
                expected_nonce="wrong-nonce",
                expected_audience="https://verifier.example.com",
            )

    def test_verify_kb_jwt_wrong_audience(
        self, sd_jwt_with_cnf, p256_private_key, p256_public_key
    ):
        sd_jwt_kb = create_kb_jwt(
            sd_jwt_with_cnf,
            p256_private_key,
            nonce="nonce",
            audience="https://real.example.com",
        )
        with pytest.raises(VerificationError, match="Audience mismatch"):
            verify_kb_jwt(
                sd_jwt_kb,
                p256_public_key,
                expected_nonce="nonce",
                expected_audience="https://evil.example.com",
            )

    def test_verify_kb_jwt_wrong_key(self, sd_jwt_with_cnf, p256_private_key):
        sd_jwt_kb = create_kb_jwt(
            sd_jwt_with_cnf,
            p256_private_key,
            nonce="nonce",
            audience="https://verifier.example.com",
        )
        _, wrong_public = generate_p256_keypair()
        with pytest.raises(VerificationError):
            verify_kb_jwt(
                sd_jwt_kb,
                wrong_public,
                expected_nonce="nonce",
                expected_audience="https://verifier.example.com",
            )


class TestTransactionData:
    def test_transaction_data_hashes(
        self, sd_jwt_with_cnf, p256_private_key, p256_public_key
    ):
        tx_data = [
            '{"type":"payment_data","payee":"Merchant XYZ","amount":"23.58 EUR"}',
            '{"type":"consent","scope":"read_profile"}',
        ]
        sd_jwt_kb = create_kb_jwt(
            sd_jwt_with_cnf,
            p256_private_key,
            nonce="tx-nonce",
            audience="https://verifier.example.com",
            transaction_data=tx_data,
        )
        payload = verify_kb_jwt(
            sd_jwt_kb,
            p256_public_key,
            expected_nonce="tx-nonce",
            expected_audience="https://verifier.example.com",
            expected_transaction_data=tx_data,
        )
        assert "transaction_data_hashes" in payload
        assert len(payload["transaction_data_hashes"]) == 2
        assert payload["transaction_data_hashes_alg"] == "sha-256"

    def test_transaction_data_mismatch(
        self, sd_jwt_with_cnf, p256_private_key, p256_public_key
    ):
        tx_data = ['{"type":"payment","amount":"100 EUR"}']
        sd_jwt_kb = create_kb_jwt(
            sd_jwt_with_cnf,
            p256_private_key,
            nonce="tx-nonce",
            audience="https://verifier.example.com",
            transaction_data=tx_data,
        )
        with pytest.raises(VerificationError, match="transaction_data_hashes"):
            verify_kb_jwt(
                sd_jwt_kb,
                p256_public_key,
                expected_nonce="tx-nonce",
                expected_audience="https://verifier.example.com",
                expected_transaction_data=['{"type":"payment","amount":"200 EUR"}'],
            )

    def test_no_transaction_data_skips_check(
        self, sd_jwt_with_cnf, p256_private_key, p256_public_key
    ):
        sd_jwt_kb = create_kb_jwt(
            sd_jwt_with_cnf,
            p256_private_key,
            nonce="nonce",
            audience="https://verifier.example.com",
        )
        payload = verify_kb_jwt(
            sd_jwt_kb,
            p256_public_key,
            expected_nonce="nonce",
            expected_audience="https://verifier.example.com",
        )
        assert "transaction_data_hashes" not in payload
