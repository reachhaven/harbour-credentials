"""Tests for harbour.delegation module.

This module tests the Harbour Delegated Signing Evidence Specification v2.

Tests cover:
- TransactionData creation and serialization
- Challenge creation and parsing
- Hash computation determinism
- Challenge verification
- Validation (timestamp, nonce, expiration)
- Human-readable display rendering
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
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

# =============================================================================
# TransactionData Tests
# =============================================================================


class TestTransactionData:
    """Tests for TransactionData dataclass."""

    def test_create_basic(self):
        """Test basic TransactionData creation."""
        tx = TransactionData.create(
            action="data.purchase",
            transaction={"assetId": "urn:uuid:test", "price": "100"},
        )

        assert tx.action == "data.purchase"
        assert tx.type == "HarbourDelegatedTransaction"
        assert tx.version == "1.0"
        assert tx.transaction == {"assetId": "urn:uuid:test", "price": "100"}
        assert tx.metadata == {}
        assert len(tx.nonce) == 8  # Default hex nonce is 8 chars
        assert tx.timestamp.endswith("Z")

    def test_create_with_custom_nonce(self):
        """Test TransactionData with custom nonce."""
        tx = TransactionData.create(
            action="data.purchase",
            transaction={"assetId": "test"},
            nonce="custom123",
        )

        assert tx.nonce == "custom123"

    def test_create_with_custom_timestamp(self):
        """Test TransactionData with custom timestamp."""
        ts = datetime(2026, 2, 24, 12, 0, 0, tzinfo=timezone.utc)
        tx = TransactionData.create(
            action="data.purchase",
            transaction={"assetId": "test"},
            timestamp=ts,
        )

        assert tx.timestamp == "2026-02-24T12:00:00Z"

    def test_create_with_metadata(self):
        """Test TransactionData with metadata."""
        tx = TransactionData.create(
            action="data.purchase",
            transaction={"assetId": "test"},
            metadata={
                "description": "Test purchase",
                "expiresAt": "2026-02-24T13:00:00Z",
            },
        )

        assert tx.metadata["description"] == "Test purchase"
        assert tx.metadata["expiresAt"] == "2026-02-24T13:00:00Z"

    def test_to_dict(self):
        """Test TransactionData.to_dict()."""
        tx = TransactionData(
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"assetId": "test", "price": "100"},
        )

        d = tx.to_dict()

        assert d["type"] == "HarbourDelegatedTransaction"
        assert d["version"] == "1.0"
        assert d["action"] == "data.purchase"
        assert d["timestamp"] == "2026-02-24T12:00:00Z"
        assert d["nonce"] == "da9b1009"
        assert d["transaction"] == {"assetId": "test", "price": "100"}
        assert d["metadata"] == {}

    def test_to_json_canonical(self):
        """Test canonical JSON output (sorted keys, no whitespace)."""
        tx = TransactionData(
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"zzzField": "last", "aaaField": "first"},
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
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"assetId": "test"},
        )

        json_str = tx.to_json(canonical=False)

        # Verify indentation
        assert "\n" in json_str
        assert "  " in json_str

    def test_from_dict(self):
        """Test TransactionData.from_dict()."""
        data = {
            "type": "HarbourDelegatedTransaction",
            "version": "1.0",
            "action": "contract.sign",
            "timestamp": "2026-02-24T12:00:00Z",
            "nonce": "ab12cd34",
            "transaction": {"documentHash": "sha256:abc123"},
            "metadata": {"expiresAt": "2026-02-24T13:00:00Z"},
        }

        tx = TransactionData.from_dict(data)

        assert tx.type == "HarbourDelegatedTransaction"
        assert tx.version == "1.0"
        assert tx.action == "contract.sign"
        assert tx.nonce == "ab12cd34"
        assert tx.transaction["documentHash"] == "sha256:abc123"
        assert tx.metadata["expiresAt"] == "2026-02-24T13:00:00Z"

    def test_from_json(self):
        """Test TransactionData.from_json()."""
        json_str = '{"action":"data.purchase","nonce":"abc12345","timestamp":"2026-02-24T12:00:00Z","transaction":{"assetId":"test"},"type":"HarbourDelegatedTransaction","version":"1.0"}'

        tx = TransactionData.from_json(json_str)

        assert tx.action == "data.purchase"
        assert tx.nonce == "abc12345"

    def test_round_trip(self):
        """Test serialization round-trip preserves data."""
        original = TransactionData.create(
            action="blockchain.transfer",
            transaction={"recipient": "0xabc", "amount": "1000"},
            metadata={"description": "Test transfer"},
        )

        # Round-trip through JSON
        json_str = original.to_json(canonical=True)
        restored = TransactionData.from_json(json_str)

        assert restored.action == original.action
        assert restored.nonce == original.nonce
        assert restored.timestamp == original.timestamp
        assert restored.transaction == original.transaction
        assert restored.metadata == original.metadata


class TestHashComputation:
    """Tests for hash computation."""

    def test_compute_hash_deterministic(self):
        """Test that hash computation is deterministic."""
        tx1 = TransactionData(
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"assetId": "test", "price": "100"},
        )

        tx2 = TransactionData(
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"assetId": "test", "price": "100"},
        )

        assert tx1.compute_hash() == tx2.compute_hash()

    def test_compute_hash_key_order_independent(self):
        """Test that hash is independent of transaction dict key order."""
        tx1 = TransactionData(
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"assetId": "test", "price": "100"},
        )

        tx2 = TransactionData(
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"price": "100", "assetId": "test"},  # Different order
        )

        # Hashes should be equal since canonical JSON sorts keys
        assert tx1.compute_hash() == tx2.compute_hash()

    def test_compute_hash_64_hex_chars(self):
        """Test that hash is 64 hex characters (SHA-256)."""
        tx = TransactionData.create(
            action="data.purchase",
            transaction={"assetId": "test"},
        )

        hash_value = tx.compute_hash()

        assert len(hash_value) == 64
        assert all(c in "0123456789abcdef" for c in hash_value)

    def test_compute_hash_changes_with_data(self):
        """Test that hash changes when data changes."""
        tx1 = TransactionData(
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"assetId": "test", "price": "100"},
        )

        tx2 = TransactionData(
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"assetId": "test", "price": "200"},  # Different price
        )

        assert tx1.compute_hash() != tx2.compute_hash()

    def test_compute_hash_sensitive_to_all_fields(self):
        """Test that hash changes for any field change."""
        base = {
            "action": "data.purchase",
            "timestamp": "2026-02-24T12:00:00Z",
            "nonce": "da9b1009",
            "transaction": {"assetId": "test"},
        }

        base_tx = TransactionData(**base)
        base_hash = base_tx.compute_hash()

        # Test each field change produces different hash
        variations = [
            {"action": "data.share"},
            {"timestamp": "2026-02-24T13:00:00Z"},
            {"nonce": "different"},
            {"transaction": {"assetId": "other"}},
        ]

        for change in variations:
            modified = {**base, **change}
            modified_tx = TransactionData(**modified)
            assert (
                modified_tx.compute_hash() != base_hash
            ), f"Hash unchanged for {change}"


# =============================================================================
# Challenge Creation Tests
# =============================================================================


class TestCreateDelegationChallenge:
    """Tests for create_delegation_challenge()."""

    def test_basic_challenge(self):
        """Test basic challenge creation."""
        tx = TransactionData(
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"assetId": "test", "price": "100"},
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
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"assetId": "test"},
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
            transaction={"assetId": "test"},
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
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"assetId": "test"},
        )

        challenge = create_delegation_challenge(tx)

        assert verify_challenge(challenge, tx) is True

    def test_verify_mismatched_nonce(self):
        """Test verification fails for mismatched nonce."""
        tx = TransactionData(
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"assetId": "test"},
        )

        # Create challenge with different nonce
        challenge = "different " + f"HARBOUR_DELEGATE {tx.compute_hash()}"

        assert verify_challenge(challenge, tx) is False

    def test_verify_mismatched_hash(self):
        """Test verification fails for mismatched hash."""
        tx = TransactionData(
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"assetId": "test"},
        )

        # Create challenge with wrong hash
        challenge = "da9b1009 HARBOUR_DELEGATE " + "b" * 64

        assert verify_challenge(challenge, tx) is False

    def test_verify_tampered_data(self):
        """Test verification fails for tampered transaction data."""
        tx = TransactionData(
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"assetId": "test", "price": "100"},
        )

        challenge = create_delegation_challenge(tx)

        # Tamper with transaction data
        tx.transaction["price"] = "999"

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
            transaction={"assetId": "test"},
        )

        # Should not raise
        validate_transaction_data(tx)

    def test_validate_invalid_type(self):
        """Test validation fails for invalid type."""
        tx = TransactionData(
            action="data.purchase",
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            nonce="da9b1009",
            transaction={"assetId": "test"},
            type="WrongType",
        )

        with pytest.raises(ChallengeError) as excinfo:
            validate_transaction_data(tx)

        assert "Invalid type" in str(excinfo.value)

    def test_validate_short_nonce(self):
        """Test validation fails for short nonce."""
        tx = TransactionData(
            action="data.purchase",
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            nonce="abc",  # Too short (< 8 chars)
            transaction={"assetId": "test"},
        )

        with pytest.raises(ChallengeError) as excinfo:
            validate_transaction_data(tx)

        assert "Nonce too short" in str(excinfo.value)

    def test_validate_old_timestamp(self):
        """Test validation fails for old timestamp."""
        old_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        tx = TransactionData(
            action="data.purchase",
            timestamp=old_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            nonce="da9b1009",
            transaction={"assetId": "test"},
        )

        with pytest.raises(ChallengeError) as excinfo:
            validate_transaction_data(tx, max_age_seconds=300)

        assert "Transaction too old" in str(excinfo.value)

    def test_validate_future_timestamp(self):
        """Test validation fails for future timestamp."""
        future_time = datetime.now(timezone.utc) + timedelta(minutes=5)
        tx = TransactionData(
            action="data.purchase",
            timestamp=future_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            nonce="da9b1009",
            transaction={"assetId": "test"},
        )

        with pytest.raises(ChallengeError) as excinfo:
            validate_transaction_data(tx)

        assert "future" in str(excinfo.value)

    def test_validate_expired_transaction(self):
        """Test validation fails for expired transaction."""
        past_expiry = datetime.now(timezone.utc) - timedelta(minutes=5)
        tx = TransactionData.create(
            action="data.purchase",
            transaction={"assetId": "test"},
            metadata={"expiresAt": past_expiry.strftime("%Y-%m-%dT%H:%M:%SZ")},
        )

        with pytest.raises(ChallengeError) as excinfo:
            validate_transaction_data(tx)

        assert "expired" in str(excinfo.value)

    def test_validate_custom_max_age(self):
        """Test validation with custom max age."""
        # 2 minutes old
        old_time = datetime.now(timezone.utc) - timedelta(seconds=120)
        tx = TransactionData(
            action="data.purchase",
            timestamp=old_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            nonce="da9b1009",
            transaction={"assetId": "test"},
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
            action="data.purchase",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={
                "assetId": "urn:uuid:test",
                "price": "100",
                "currency": "ENVITED",
            },
        )

        display = render_transaction_display(tx)

        assert "requests your authorization" in display
        assert "Purchase data asset" in display  # Human-readable label
        assert "da9b1009" in display
        assert "2026-02-24T12:00:00Z" in display

    def test_render_custom_service_name(self):
        """Test display with custom service name."""
        tx = TransactionData.create(
            action="data.purchase",
            transaction={"assetId": "test"},
        )

        display = render_transaction_display(tx, service_name="Custom Service")

        assert "Custom Service requests your authorization" in display

    def test_render_unknown_action(self):
        """Test display with unknown action type."""
        tx = TransactionData(
            action="unknown.action",
            timestamp="2026-02-24T12:00:00Z",
            nonce="da9b1009",
            transaction={"someField": "value"},
        )

        display = render_transaction_display(tx)

        # Should convert "unknown.action" to "Unknown Action"
        assert "Unknown Action" in display

    def test_render_with_expiration(self):
        """Test display includes expiration if present."""
        tx = TransactionData.create(
            action="data.purchase",
            transaction={"assetId": "test"},
            metadata={"expiresAt": "2026-02-24T13:00:00Z"},
        )

        display = render_transaction_display(tx)

        assert "Expires:" in display
        assert "2026-02-24T13:00:00Z" in display

    def test_render_with_description(self):
        """Test display includes description if present."""
        tx = TransactionData.create(
            action="data.purchase",
            transaction={"assetId": "test"},
            metadata={"description": "Purchase sensor data from BMW"},
        )

        display = render_transaction_display(tx)

        assert "Details:" in display
        assert "Purchase sensor data from BMW" in display

    def test_render_truncates_long_values(self):
        """Test display truncates very long values."""
        tx = TransactionData.create(
            action="data.purchase",
            transaction={"assetId": "a" * 100},  # Very long value
        )

        display = render_transaction_display(tx)

        # Should be truncated with ellipsis
        assert "..." in display

    def test_render_all_action_labels(self):
        """Test that all known action labels are rendered correctly."""
        for action, label in ACTION_LABELS.items():
            tx = TransactionData.create(
                action=action,
                transaction={"testField": "value"},
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
            transaction={
                "assetId": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
                "price": "100",
                "currency": "ENVITED",
            },
            metadata={"description": "Purchase sensor data"},
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
            transaction={"documentHash": "sha256:abc123"},
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
                transaction={"assetId": f"asset-{i}"},
            )
            hashes.add(tx.compute_hash())

        # All hashes should be unique
        assert len(hashes) == 10
