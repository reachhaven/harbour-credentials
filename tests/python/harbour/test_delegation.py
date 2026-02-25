"""Tests for harbour.delegation module.

This module tests the Harbour Delegated Signing Evidence Specification v2
with OID4VP-aligned TransactionData.

Tests cover:
- TransactionData creation and serialization (OID4VP fields)
- Challenge creation and parsing
- Hash computation determinism
- Challenge verification
- Validation (timestamp, nonce, expiration)
- Human-readable display rendering
- Shared canonicalization test vectors
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from harbour.delegation import (
    ACTION_LABELS,
    ACTION_TYPE,
    ChallengeError,
    TransactionData,
    create_delegation_challenge,
    parse_delegation_challenge,
    render_transaction_display,
    validate_transaction_data,
    verify_challenge,
)

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"


# =============================================================================
# TransactionData Tests
# =============================================================================


class TestTransactionData:
    """Tests for TransactionData dataclass."""

    def test_create_basic(self):
        """Test basic TransactionData creation."""
        tx = TransactionData.create(
            action="data.purchase",
            txn={"assetId": "urn:uuid:test", "price": "100"},
        )

        assert tx.type == "harbour_delegate:data.purchase"
        assert tx.credential_ids == ["default"]
        assert tx.txn == {"assetId": "urn:uuid:test", "price": "100"}
        assert tx.exp is None
        assert tx.description is None
        assert tx.transaction_data_hashes_alg == ["sha-256"]
        assert len(tx.nonce) == 8  # Default hex nonce is 8 chars
        assert isinstance(tx.iat, int)

    def test_create_with_custom_nonce(self):
        """Test TransactionData with custom nonce."""
        tx = TransactionData.create(
            action="data.purchase",
            txn={"assetId": "test"},
            nonce="custom123",
        )

        assert tx.nonce == "custom123"

    def test_create_with_custom_iat(self):
        """Test TransactionData with custom iat."""
        tx = TransactionData.create(
            action="data.purchase",
            txn={"assetId": "test"},
            iat=1771934400,
        )

        assert tx.iat == 1771934400

    def test_create_with_optional_fields(self):
        """Test TransactionData with optional fields."""
        tx = TransactionData.create(
            action="data.purchase",
            txn={"assetId": "test"},
            exp=1771935300,
            description="Test purchase",
            credential_ids=["simpulse_id"],
        )

        assert tx.exp == 1771935300
        assert tx.description == "Test purchase"
        assert tx.credential_ids == ["simpulse_id"]

    def test_action_property(self):
        """Test action extraction from type field."""
        tx = TransactionData.create(
            action="data.purchase",
            txn={"assetId": "test"},
        )

        assert tx.action == "data.purchase"

    def test_to_dict_omits_none(self):
        """Test TransactionData.to_dict() omits None values."""
        tx = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"assetId": "test", "price": "100"},
        )

        d = tx.to_dict()

        assert d["type"] == "harbour_delegate:data.purchase"
        assert d["credential_ids"] == ["default"]
        assert d["nonce"] == "da9b1009"
        assert d["iat"] == 1771934400
        assert d["txn"] == {"assetId": "test", "price": "100"}
        assert "exp" not in d
        assert "description" not in d

    def test_to_dict_includes_optional_when_present(self):
        """Test TransactionData.to_dict() includes optional fields when set."""
        tx = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["simpulse_id"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"assetId": "test"},
            exp=1771935300,
            description="Test purchase",
        )

        d = tx.to_dict()
        assert d["exp"] == 1771935300
        assert d["description"] == "Test purchase"

    def test_to_json_canonical(self):
        """Test canonical JSON output (sorted keys, no whitespace)."""
        tx = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"zzzField": "last", "aaaField": "first"},
        )

        json_str = tx.to_json(canonical=True)

        # Verify no whitespace
        assert " " not in json_str
        assert "\n" not in json_str

        # Verify sorted keys (aaaField before zzzField)
        assert json_str.index("aaaField") < json_str.index("zzzField")

    def test_to_json_pretty(self):
        """Test pretty JSON output."""
        tx = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"assetId": "test"},
        )

        json_str = tx.to_json(canonical=False)

        # Verify indentation
        assert "\n" in json_str
        assert "  " in json_str

    def test_from_dict(self):
        """Test TransactionData.from_dict()."""
        data = {
            "type": "harbour_delegate:contract.sign",
            "credential_ids": ["org_credential"],
            "nonce": "ab12cd34",
            "iat": 1771934400,
            "exp": 1771935300,
            "description": "Sign agreement",
            "txn": {"documentHash": "sha256:abc123"},
            "transaction_data_hashes_alg": ["sha-256"],
        }

        tx = TransactionData.from_dict(data)

        assert tx.type == "harbour_delegate:contract.sign"
        assert tx.credential_ids == ["org_credential"]
        assert tx.nonce == "ab12cd34"
        assert tx.iat == 1771934400
        assert tx.exp == 1771935300
        assert tx.description == "Sign agreement"
        assert tx.txn["documentHash"] == "sha256:abc123"

    def test_from_json(self):
        """Test TransactionData.from_json()."""
        json_str = json.dumps(
            {
                "type": "harbour_delegate:data.purchase",
                "credential_ids": ["default"],
                "nonce": "abc12345",
                "iat": 1771934400,
                "txn": {"assetId": "test"},
            }
        )

        tx = TransactionData.from_json(json_str)

        assert tx.action == "data.purchase"
        assert tx.nonce == "abc12345"

    def test_round_trip(self):
        """Test serialization round-trip preserves data."""
        original = TransactionData.create(
            action="blockchain.transfer",
            txn={"recipient": "0xabc", "amount": "1000"},
            description="Test transfer",
            credential_ids=["wallet_cred"],
        )

        # Round-trip through JSON
        json_str = original.to_json(canonical=True)
        restored = TransactionData.from_json(json_str)

        assert restored.type == original.type
        assert restored.action == original.action
        assert restored.nonce == original.nonce
        assert restored.iat == original.iat
        assert restored.txn == original.txn
        assert restored.description == original.description
        assert restored.credential_ids == original.credential_ids


class TestHashComputation:
    """Tests for hash computation."""

    def test_compute_hash_deterministic(self):
        """Test that hash computation is deterministic."""
        tx1 = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"assetId": "test", "price": "100"},
        )

        tx2 = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"assetId": "test", "price": "100"},
        )

        assert tx1.compute_hash() == tx2.compute_hash()

    def test_compute_hash_key_order_independent(self):
        """Test that hash is independent of transaction dict key order."""
        tx1 = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"assetId": "test", "price": "100"},
        )

        tx2 = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"price": "100", "assetId": "test"},  # Different order
        )

        # Hashes should be equal since canonical JSON sorts keys
        assert tx1.compute_hash() == tx2.compute_hash()

    def test_compute_hash_64_hex_chars(self):
        """Test that hash is 64 hex characters (SHA-256)."""
        tx = TransactionData.create(
            action="data.purchase",
            txn={"assetId": "test"},
        )

        hash_value = tx.compute_hash()

        assert len(hash_value) == 64
        assert all(c in "0123456789abcdef" for c in hash_value)

    def test_compute_hash_changes_with_data(self):
        """Test that hash changes when data changes."""
        tx1 = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"assetId": "test", "price": "100"},
        )

        tx2 = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"assetId": "test", "price": "200"},  # Different price
        )

        assert tx1.compute_hash() != tx2.compute_hash()

    def test_compute_hash_sensitive_to_all_fields(self):
        """Test that hash changes for any field change."""
        base = {
            "type": "harbour_delegate:data.purchase",
            "credential_ids": ["default"],
            "nonce": "da9b1009",
            "iat": 1771934400,
            "txn": {"assetId": "test"},
        }

        base_tx = TransactionData(**base)
        base_hash = base_tx.compute_hash()

        # Test each field change produces different hash
        variations = [
            {"type": "harbour_delegate:data.share"},
            {"credential_ids": ["other"]},
            {"nonce": "different"},
            {"iat": 9999999999},
            {"txn": {"assetId": "other"}},
        ]

        for change in variations:
            modified = {**base, **change}
            modified_tx = TransactionData(**modified)
            assert (
                modified_tx.compute_hash() != base_hash
            ), f"Hash unchanged for {change}"


class TestSharedVectors:
    """Tests using shared canonicalization test vectors."""

    @pytest.fixture
    def vectors(self):
        """Load shared test vectors."""
        vectors_path = FIXTURES_DIR / "canonicalization-vectors.json"
        return json.loads(vectors_path.read_text())["vectors"]

    def test_canonical_json_matches(self, vectors):
        """Test that Python canonical JSON matches expected output."""
        for v in vectors:
            tx = TransactionData.from_dict(v["input"])
            canonical = tx.to_json(canonical=True)
            assert canonical == v["canonical_json"], (
                f"Canonical JSON mismatch for '{v['name']}':\n"
                f"  got:      {canonical}\n"
                f"  expected: {v['canonical_json']}"
            )

    def test_sha256_hash_matches(self, vectors):
        """Test that Python SHA-256 hash matches expected output."""
        for v in vectors:
            tx = TransactionData.from_dict(v["input"])
            hash_value = tx.compute_hash()
            assert hash_value == v["sha256_hash"], (
                f"SHA-256 hash mismatch for '{v['name']}':\n"
                f"  got:      {hash_value}\n"
                f"  expected: {v['sha256_hash']}"
            )

    def test_challenge_matches(self, vectors):
        """Test that challenge string matches expected output."""
        for v in vectors:
            tx = TransactionData.from_dict(v["input"])
            challenge = create_delegation_challenge(tx)
            assert challenge == v["challenge"], (
                f"Challenge mismatch for '{v['name']}':\n"
                f"  got:      {challenge}\n"
                f"  expected: {v['challenge']}"
            )


# =============================================================================
# Challenge Creation Tests
# =============================================================================


class TestCreateDelegationChallenge:
    """Tests for create_delegation_challenge()."""

    def test_basic_challenge(self):
        """Test basic challenge creation."""
        tx = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"assetId": "test", "price": "100"},
        )

        challenge = create_delegation_challenge(tx)
        parts = challenge.split(" ")

        assert len(parts) == 3
        assert parts[0] == "da9b1009"  # nonce
        assert parts[1] == "HARBOUR_DELEGATE"  # action type
        assert len(parts[2]) == 64  # SHA-256 hash

    def test_challenge_matches_hash(self):
        """Test that challenge hash matches computed hash."""
        tx = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"assetId": "test"},
        )

        challenge = create_delegation_challenge(tx)
        _, _, challenge_hash = challenge.split(" ")

        assert challenge_hash == tx.compute_hash()


# =============================================================================
# Challenge Parsing Tests
# =============================================================================


class TestParseDelegationChallenge:
    """Tests for parse_delegation_challenge()."""

    def test_parse_valid_challenge(self):
        """Test parsing a valid challenge."""
        challenge = "da9b1009 HARBOUR_DELEGATE " + "a" * 64

        nonce, action_type, tx_hash = parse_delegation_challenge(challenge)

        assert nonce == "da9b1009"
        assert action_type == "HARBOUR_DELEGATE"
        assert tx_hash == "a" * 64

    def test_parse_invalid_part_count(self):
        """Test that invalid part count raises error."""
        with pytest.raises(ChallengeError) as excinfo:
            parse_delegation_challenge("only")

        assert "expected 3" in str(excinfo.value)

    def test_parse_invalid_action_type(self):
        """Test that invalid action type raises error."""
        challenge = "da9b1009 WRONG_ACTION " + "a" * 64

        with pytest.raises(ChallengeError) as excinfo:
            parse_delegation_challenge(challenge)

        assert "Invalid action type" in str(excinfo.value)

    def test_parse_invalid_hash_length(self):
        """Test that invalid hash length raises error."""
        challenge = "da9b1009 HARBOUR_DELEGATE tooshort"

        with pytest.raises(ChallengeError) as excinfo:
            parse_delegation_challenge(challenge)

        assert "Invalid hash length" in str(excinfo.value)

    def test_parse_invalid_hash_hex(self):
        """Test that non-hex hash raises error."""
        challenge = "da9b1009 HARBOUR_DELEGATE " + "g" * 64  # 'g' is not valid hex

        with pytest.raises(ChallengeError) as excinfo:
            parse_delegation_challenge(challenge)

        assert "not valid hexadecimal" in str(excinfo.value)

    def test_round_trip(self):
        """Test create -> parse round-trip."""
        tx = TransactionData.create(
            action="data.purchase",
            txn={"assetId": "test"},
        )

        challenge = create_delegation_challenge(tx)
        nonce, action_type, tx_hash = parse_delegation_challenge(challenge)

        assert nonce == tx.nonce
        assert action_type == ACTION_TYPE
        assert tx_hash == tx.compute_hash()


# =============================================================================
# Challenge Verification Tests
# =============================================================================


class TestVerifyChallenge:
    """Tests for verify_challenge()."""

    def test_verify_matching_challenge(self):
        """Test verification of matching challenge."""
        tx = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"assetId": "test"},
        )

        challenge = create_delegation_challenge(tx)

        assert verify_challenge(challenge, tx) is True

    def test_verify_mismatched_nonce(self):
        """Test verification fails for mismatched nonce."""
        tx = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"assetId": "test"},
        )

        # Create challenge with different nonce
        challenge = "different " + f"HARBOUR_DELEGATE {tx.compute_hash()}"

        assert verify_challenge(challenge, tx) is False

    def test_verify_mismatched_hash(self):
        """Test verification fails for mismatched hash."""
        tx = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"assetId": "test"},
        )

        # Create challenge with wrong hash
        challenge = "da9b1009 HARBOUR_DELEGATE " + "b" * 64

        assert verify_challenge(challenge, tx) is False

    def test_verify_tampered_data(self):
        """Test verification fails for tampered transaction data."""
        tx = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"assetId": "test", "price": "100"},
        )

        challenge = create_delegation_challenge(tx)

        # Tamper with transaction data
        tx.txn["price"] = "999"

        assert verify_challenge(challenge, tx) is False


# =============================================================================
# Transaction Validation Tests
# =============================================================================


class TestValidateTransactionData:
    """Tests for validate_transaction_data()."""

    def test_validate_valid_transaction(self):
        """Test validation of valid transaction."""
        tx = TransactionData.create(
            action="data.purchase",
            txn={"assetId": "test"},
        )

        # Should not raise
        validate_transaction_data(tx)

    def test_validate_invalid_type(self):
        """Test validation fails for invalid type prefix."""
        tx = TransactionData(
            type="wrong_prefix:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=int(time.time()),
            txn={"assetId": "test"},
        )

        with pytest.raises(ChallengeError) as excinfo:
            validate_transaction_data(tx)

        assert "Invalid type" in str(excinfo.value)

    def test_validate_short_nonce(self):
        """Test validation fails for short nonce."""
        tx = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="abc",  # Too short (< 8 chars)
            iat=int(time.time()),
            txn={"assetId": "test"},
        )

        with pytest.raises(ChallengeError) as excinfo:
            validate_transaction_data(tx)

        assert "Nonce too short" in str(excinfo.value)

    def test_validate_old_timestamp(self):
        """Test validation fails for old timestamp."""
        old_iat = int(time.time()) - 600  # 10 minutes ago
        tx = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=old_iat,
            txn={"assetId": "test"},
        )

        with pytest.raises(ChallengeError) as excinfo:
            validate_transaction_data(tx, max_age_seconds=300)

        assert "Transaction too old" in str(excinfo.value)

    def test_validate_future_timestamp(self):
        """Test validation fails for future timestamp."""
        future_iat = int(time.time()) + 300  # 5 minutes in future
        tx = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=future_iat,
            txn={"assetId": "test"},
        )

        with pytest.raises(ChallengeError) as excinfo:
            validate_transaction_data(tx)

        assert "future" in str(excinfo.value)

    def test_validate_expired_transaction(self):
        """Test validation fails for expired transaction."""
        now = int(time.time())
        tx = TransactionData.create(
            action="data.purchase",
            txn={"assetId": "test"},
            exp=now - 300,  # Expired 5 minutes ago
        )

        with pytest.raises(ChallengeError) as excinfo:
            validate_transaction_data(tx)

        assert "expired" in str(excinfo.value)

    def test_validate_custom_max_age(self):
        """Test validation with custom max age."""
        # 2 minutes old
        old_iat = int(time.time()) - 120
        tx = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=old_iat,
            txn={"assetId": "test"},
        )

        # Should fail with 60s max age
        with pytest.raises(ChallengeError):
            validate_transaction_data(tx, max_age_seconds=60)

        # Should pass with 300s max age
        validate_transaction_data(tx, max_age_seconds=300)


# =============================================================================
# Human Display Tests
# =============================================================================


class TestRenderTransactionDisplay:
    """Tests for render_transaction_display()."""

    def test_render_basic(self):
        """Test basic display rendering."""
        tx = TransactionData(
            type="harbour_delegate:data.purchase",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={
                "assetId": "urn:uuid:test",
                "price": "100",
                "currency": "ENVITED",
            },
        )

        display = render_transaction_display(tx)

        assert "requests your authorization" in display
        assert "Purchase data asset" in display  # Human-readable label
        assert "da9b1009" in display
        assert "1771934400" in display

    def test_render_custom_service_name(self):
        """Test display with custom service name."""
        tx = TransactionData.create(
            action="data.purchase",
            txn={"assetId": "test"},
        )

        display = render_transaction_display(tx, service_name="Custom Service")

        assert "Custom Service requests your authorization" in display

    def test_render_unknown_action(self):
        """Test display with unknown action type."""
        tx = TransactionData(
            type="harbour_delegate:unknown.action",
            credential_ids=["default"],
            nonce="da9b1009",
            iat=1771934400,
            txn={"someField": "value"},
        )

        display = render_transaction_display(tx)

        # Should convert "unknown.action" to "Unknown Action"
        assert "Unknown Action" in display

    def test_render_with_expiration(self):
        """Test display includes expiration if present."""
        tx = TransactionData.create(
            action="data.purchase",
            txn={"assetId": "test"},
            exp=1771935300,
        )

        display = render_transaction_display(tx)

        assert "Expires:" in display
        assert "1771935300" in display

    def test_render_with_description(self):
        """Test display includes description if present."""
        tx = TransactionData.create(
            action="data.purchase",
            txn={"assetId": "test"},
            description="Purchase sensor data from BMW",
        )

        display = render_transaction_display(tx)

        assert "Details:" in display
        assert "Purchase sensor data from BMW" in display

    def test_render_truncates_long_values(self):
        """Test display truncates very long values."""
        tx = TransactionData.create(
            action="data.purchase",
            txn={"assetId": "a" * 100},  # Very long value
        )

        display = render_transaction_display(tx)

        # Should be truncated with ellipsis
        assert "..." in display

    def test_render_all_action_labels(self):
        """Test that all known action labels are rendered correctly."""
        for action, label in ACTION_LABELS.items():
            tx = TransactionData.create(
                action=action,
                txn={"testField": "value"},
            )

            display = render_transaction_display(tx)

            assert label in display, f"Label '{label}' not found for action '{action}'"


# =============================================================================
# CLI Tests
# =============================================================================


class TestCLI:
    """Tests for CLI functionality."""

    def test_main_create_command(self, capsys):
        """Test CLI create command."""
        import sys

        from harbour.delegation import main

        with patch.object(
            sys,
            "argv",
            [
                "delegation",
                "create",
                "--action",
                "data.purchase",
                "--asset-id",
                "urn:uuid:test",
                "--price",
                "100",
            ],
        ):
            main()

        captured = capsys.readouterr()
        assert "Challenge:" in captured.out
        assert "HARBOUR_DELEGATE" in captured.out

    def test_main_parse_command(self, capsys):
        """Test CLI parse command."""
        import sys

        from harbour.delegation import main

        challenge = "da9b1009 HARBOUR_DELEGATE " + "a" * 64

        with patch.object(sys, "argv", ["delegation", "parse", challenge]):
            main()

        captured = capsys.readouterr()
        assert "Nonce: da9b1009" in captured.out
        assert "Action Type: HARBOUR_DELEGATE" in captured.out

    def test_main_no_command_shows_help(self, capsys):
        """Test CLI with no command shows help."""
        import sys

        from harbour.delegation import main

        with patch.object(sys, "argv", ["delegation"]):
            with pytest.raises(SystemExit) as excinfo:
                main()

        assert excinfo.value.code == 1

    def test_main_parse_invalid_challenge(self, capsys):
        """Test CLI parse with invalid challenge exits with error."""
        import sys

        from harbour.delegation import main

        with patch.object(sys, "argv", ["delegation", "parse", "invalid"]):
            with pytest.raises(SystemExit) as excinfo:
                main()

        assert excinfo.value.code == 1
        captured = capsys.readouterr()
        assert "Error:" in captured.err


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for the full delegation workflow."""

    def test_full_workflow(self):
        """Test complete delegation workflow."""
        # 1. Create transaction data
        tx = TransactionData.create(
            action="data.purchase",
            txn={
                "assetId": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
                "price": "100",
                "currency": "ENVITED",
            },
            description="Purchase sensor data",
            credential_ids=["simpulse_id"],
        )

        # 2. Create challenge
        challenge = create_delegation_challenge(tx)

        # 3. Parse challenge
        nonce, action_type, tx_hash = parse_delegation_challenge(challenge)

        assert nonce == tx.nonce
        assert action_type == "HARBOUR_DELEGATE"

        # 4. Verify challenge matches transaction data
        assert verify_challenge(challenge, tx)

        # 5. Validate transaction data
        validate_transaction_data(tx)

        # 6. Render for human display
        display = render_transaction_display(tx)
        assert "Purchase data asset" in display

    def test_serialization_workflow(self):
        """Test serialization/deserialization in workflow."""
        # Create and serialize
        original_tx = TransactionData.create(
            action="contract.sign",
            txn={"documentHash": "sha256:abc123"},
        )
        challenge = create_delegation_challenge(original_tx)
        tx_json = original_tx.to_json()

        # Simulate transmission: deserialize
        restored_tx = TransactionData.from_json(tx_json)

        # Verify challenge against restored data
        assert verify_challenge(challenge, restored_tx)

    def test_multiple_transactions_unique_hashes(self):
        """Test that multiple transactions produce unique hashes."""
        hashes = set()

        for i in range(10):
            tx = TransactionData.create(
                action="data.purchase",
                txn={"assetId": f"asset-{i}"},
            )
            hashes.add(tx.compute_hash())

        # All hashes should be unique
        assert len(hashes) == 10
