"""Harbour Delegated Signing Evidence.

This module implements the Harbour Delegated Signing Evidence Specification v2
for creating and verifying delegation challenges used in VP proof.challenge fields.

The challenge format is: <nonce> HARBOUR_DELEGATE <sha256-hash>

Where the hash is computed over a canonical JSON representation of the
transaction data object.

See docs/specs/delegation-challenge-encoding.md for the full specification.

CLI Usage:
    python -m harbour.delegation --help
    python -m harbour.delegation create --action data.purchase --asset-id "urn:uuid:..." --price 100
    python -m harbour.delegation parse "da9b1009 HARBOUR_DELEGATE abc123..."
    python -m harbour.delegation display transaction.json
    python -m harbour.delegation verify "challenge" transaction.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

# Action type identifier
ACTION_TYPE = "HARBOUR_DELEGATE"

# Human-friendly labels for action types
ACTION_LABELS = {
    "blockchain.transfer": "Transfer tokens",
    "blockchain.approve": "Approve token spending",
    "blockchain.execute": "Execute smart contract",
    "blockchain.sign": "Sign blockchain message",
    "contract.sign": "Sign contract",
    "contract.accept": "Accept agreement",
    "contract.reject": "Reject agreement",
    "data.purchase": "Purchase data asset",
    "data.share": "Share data",
    "data.access": "Access data",
    "credential.issue": "Issue credential",
    "credential.revoke": "Revoke credential",
    "credential.present": "Present credential",
}


class ChallengeError(ValueError):
    """Error parsing or validating a delegation challenge."""

    pass


@dataclass
class TransactionData:
    """Full transaction data object for delegated signing.

    This object contains all details about the transaction being authorized.
    The challenge contains only a hash of this object for compactness.

    Attributes:
        action: The action being delegated (e.g., "data.purchase")
        timestamp: ISO8601 timestamp when the transaction was created
        nonce: Unique identifier for replay protection
        transaction: Action-specific transaction details
        type: Fixed type identifier (HarbourDelegatedTransaction)
        version: Schema version (1.0)
        metadata: Optional additional context (description, expiration, etc.)
    """

    action: str
    timestamp: str
    nonce: str
    transaction: dict[str, Any]
    type: str = "HarbourDelegatedTransaction"
    version: str = "1.0"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)

    def to_json(self, canonical: bool = True) -> str:
        """Convert to JSON string.

        Args:
            canonical: If True, use canonical form (sorted keys, no whitespace)
        """
        if canonical:
            return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return json.dumps(self.to_dict(), indent=2)

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of canonical JSON representation.

        Returns:
            Lowercase hex-encoded SHA-256 hash (64 characters)
        """
        canonical = self.to_json(canonical=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TransactionData:
        """Create from dictionary."""
        return cls(
            action=data["action"],
            timestamp=data["timestamp"],
            nonce=data["nonce"],
            transaction=data["transaction"],
            type=data.get("type", "HarbourDelegatedTransaction"),
            version=data.get("version", "1.0"),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_json(cls, json_str: str) -> TransactionData:
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def create(
        cls,
        action: str,
        transaction: dict[str, Any],
        *,
        nonce: str | None = None,
        timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TransactionData:
        """Create a new transaction data object.

        Args:
            action: The action being delegated
            transaction: Action-specific transaction details
            nonce: Unique identifier (auto-generated if not provided)
            timestamp: Transaction timestamp (defaults to now)
            metadata: Optional additional context
        """
        if nonce is None:
            nonce = secrets.token_hex(4)  # 8 hex characters

        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        return cls(
            action=action,
            timestamp=timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            nonce=nonce,
            transaction=transaction,
            metadata=metadata or {},
        )


def create_delegation_challenge(transaction_data: TransactionData) -> str:
    """Create a Harbour delegation challenge string.

    Format: <nonce> HARBOUR_DELEGATE <sha256-hash>

    Args:
        transaction_data: The full transaction data object

    Returns:
        Challenge string suitable for VP proof.challenge field

    Example:
        >>> tx = TransactionData.create(
        ...     action="data.purchase",
        ...     transaction={"assetId": "urn:uuid:...", "price": "100"},
        ... )
        >>> challenge = create_delegation_challenge(tx)
        >>> print(challenge)
        da9b1009 HARBOUR_DELEGATE abc123...
    """
    tx_hash = transaction_data.compute_hash()
    return f"{transaction_data.nonce} {ACTION_TYPE} {tx_hash}"


def parse_delegation_challenge(challenge: str) -> tuple[str, str, str]:
    """Parse a Harbour delegation challenge string.

    Args:
        challenge: The challenge string to parse

    Returns:
        Tuple of (nonce, action_type, hash)

    Raises:
        ChallengeError: If the challenge format is invalid

    Example:
        >>> nonce, action_type, tx_hash = parse_delegation_challenge(challenge)
        >>> print(f"Nonce: {nonce}, Hash: {tx_hash[:16]}...")
    """
    parts = challenge.split(" ")
    if len(parts) != 3:
        raise ChallengeError(
            f"Invalid challenge format: expected 3 space-separated parts, got {len(parts)}"
        )

    nonce, action_type, tx_hash = parts

    if action_type != ACTION_TYPE:
        raise ChallengeError(
            f"Invalid action type: expected '{ACTION_TYPE}', got '{action_type}'"
        )

    if len(tx_hash) != 64:
        raise ChallengeError(
            f"Invalid hash length: expected 64 hex characters, got {len(tx_hash)}"
        )

    # Validate hash is valid hex
    try:
        int(tx_hash, 16)
    except ValueError:
        raise ChallengeError("Invalid hash: not valid hexadecimal")

    return nonce, action_type, tx_hash


def verify_challenge(
    challenge: str,
    transaction_data: TransactionData,
) -> bool:
    """Verify that a challenge matches transaction data.

    Args:
        challenge: The challenge string to verify
        transaction_data: The transaction data to verify against

    Returns:
        True if the hash in the challenge matches the transaction data

    Example:
        >>> if verify_challenge(challenge, tx):
        ...     print("Challenge is valid!")
    """
    nonce, _, challenge_hash = parse_delegation_challenge(challenge)

    if nonce != transaction_data.nonce:
        return False

    computed_hash = transaction_data.compute_hash()
    return challenge_hash == computed_hash


def render_transaction_display(
    transaction_data: TransactionData,
    service_name: str = "Harbour Signing Service",
) -> str:
    """Render transaction data for human-readable display.

    This follows the SIWE (EIP-4361) philosophy of presenting users with
    clear, readable consent prompts.

    Args:
        transaction_data: The transaction data to display
        service_name: Human-friendly name for the signing service

    Returns:
        Multi-line string suitable for display to user
    """
    action = transaction_data.action
    action_label = ACTION_LABELS.get(action, action.replace(".", " ").title())

    lines = [
        f"{service_name} requests your authorization",
        "─" * 50,
        "",
        f"  Action:      {action_label}",
    ]

    # Add transaction-specific fields
    for key, value in transaction_data.transaction.items():
        display_key = key.replace("_", " ").replace("Id", " ID").title()
        display_value = str(value)
        if len(display_value) > 40:
            display_value = display_value[:37] + "..."
        lines.append(f"  {display_key}:  {display_value}")

    lines.extend(
        [
            "",
            "─" * 50,
            f"  Nonce:       {transaction_data.nonce}",
            f"  Time:        {transaction_data.timestamp}",
        ]
    )

    if transaction_data.metadata.get("expiresAt"):
        lines.append(f"  Expires:     {transaction_data.metadata['expiresAt']}")

    if transaction_data.metadata.get("description"):
        lines.append(f"  Details:     {transaction_data.metadata['description']}")

    return "\n".join(lines)


def validate_transaction_data(
    transaction_data: TransactionData,
    *,
    max_age_seconds: int = 300,
) -> None:
    """Validate transaction data for security requirements.

    Args:
        transaction_data: The transaction data to validate
        max_age_seconds: Maximum age of the transaction in seconds (default: 5 minutes)

    Raises:
        ChallengeError: If validation fails
    """
    # Validate type
    if transaction_data.type != "HarbourDelegatedTransaction":
        raise ChallengeError(
            f"Invalid type: expected 'HarbourDelegatedTransaction', got '{transaction_data.type}'"
        )

    # Validate nonce length (minimum 8 hex characters = 32 bits)
    if len(transaction_data.nonce) < 8:
        raise ChallengeError(
            f"Nonce too short: {len(transaction_data.nonce)} chars (minimum 8)"
        )

    # Parse and validate timestamp
    try:
        ts = datetime.strptime(
            transaction_data.timestamp, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError as e:
        raise ChallengeError(f"Invalid timestamp format: {e}") from e

    now = datetime.now(timezone.utc)
    age = (now - ts).total_seconds()

    if age > max_age_seconds:
        raise ChallengeError(
            f"Transaction too old: {age:.0f}s (max {max_age_seconds}s)"
        )

    if age < -60:  # Allow 1 minute clock skew
        raise ChallengeError(
            f"Transaction timestamp is in the future: {transaction_data.timestamp}"
        )

    # Check expiration if present
    if transaction_data.metadata.get("expiresAt"):
        try:
            exp = datetime.strptime(
                transaction_data.metadata["expiresAt"], "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
        except ValueError as e:
            raise ChallengeError(f"Invalid expiration format: {e}") from e

        if now > exp:
            raise ChallengeError(
                f"Transaction expired at {transaction_data.metadata['expiresAt']}"
            )


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="harbour.delegation",
        description="Harbour Delegated Signing Evidence CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create a delegation challenge for a data purchase
  python -m harbour.delegation create \\
    --action data.purchase \\
    --asset-id "urn:uuid:550e8400-e29b-41d4-a716-446655440000" \\
    --price 100 --currency ENVITED

  # Parse a challenge string
  python -m harbour.delegation parse "da9b1009 HARBOUR_DELEGATE abc123..."

  # Display transaction data in human-readable format
  python -m harbour.delegation display transaction.json

  # Verify a challenge against transaction data
  python -m harbour.delegation verify "da9b1009 HARBOUR_DELEGATE abc123..." transaction.json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Create command
    create_parser = subparsers.add_parser(
        "create", help="Create a delegation challenge"
    )
    create_parser.add_argument(
        "--action", required=True, help="Action type (e.g., data.purchase)"
    )
    create_parser.add_argument("--asset-id", help="Asset ID for data purchases")
    create_parser.add_argument("--price", help="Price/amount")
    create_parser.add_argument("--currency", help="Currency/token")
    create_parser.add_argument("--chain", help="Blockchain chain ID")
    create_parser.add_argument("--contract", help="Contract address")
    create_parser.add_argument("--recipient", help="Recipient address")
    create_parser.add_argument("--desc", help="Description")
    create_parser.add_argument("--exp-minutes", type=int, help="Expiration in minutes")
    create_parser.add_argument(
        "--output-json", action="store_true", help="Output full JSON"
    )

    # Parse command
    parse_parser = subparsers.add_parser("parse", help="Parse a delegation challenge")
    parse_parser.add_argument("challenge", help="The challenge string to parse")

    # Display command
    display_parser = subparsers.add_parser(
        "display", help="Display transaction in human format"
    )
    display_parser.add_argument("json_file", help="JSON file with transaction data")
    display_parser.add_argument(
        "--service", default="Harbour Signing Service", help="Service name"
    )

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a challenge")
    verify_parser.add_argument("challenge", help="The challenge string to verify")
    verify_parser.add_argument("json_file", help="JSON file with transaction data")
    verify_parser.add_argument(
        "--max-age", type=int, default=300, help="Max age in seconds"
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == "create":
            # Build transaction dict from args
            transaction = {}
            if args.asset_id:
                transaction["assetId"] = args.asset_id
            if args.price:
                transaction["price"] = args.price
            if args.currency:
                transaction["currency"] = args.currency
            if args.chain:
                transaction["chain"] = args.chain
            if args.contract:
                transaction["contract"] = args.contract
            if args.recipient:
                transaction["recipient"] = args.recipient

            metadata = {}
            if args.desc:
                metadata["description"] = args.desc
            if args.exp_minutes:
                from datetime import timedelta

                exp = datetime.now(timezone.utc) + timedelta(minutes=args.exp_minutes)
                metadata["expiresAt"] = exp.strftime("%Y-%m-%dT%H:%M:%SZ")

            tx = TransactionData.create(
                action=args.action,
                transaction=transaction,
                metadata=metadata if metadata else None,
            )

            if args.output_json:
                print(tx.to_json(canonical=False))
            else:
                challenge = create_delegation_challenge(tx)
                print(f"Challenge: {challenge}")
                print(f"Hash: {tx.compute_hash()}")
                print(f"Nonce: {tx.nonce}")

        elif args.command == "parse":
            nonce, action_type, tx_hash = parse_delegation_challenge(args.challenge)
            print(f"Nonce: {nonce}")
            print(f"Action Type: {action_type}")
            print(f"Hash: {tx_hash}")

        elif args.command == "display":
            with open(args.json_file, "r") as f:
                tx = TransactionData.from_json(f.read())
            print(render_transaction_display(tx, args.service))

        elif args.command == "verify":
            with open(args.json_file, "r") as f:
                tx = TransactionData.from_json(f.read())

            validate_transaction_data(tx, max_age_seconds=args.max_age)

            if verify_challenge(args.challenge, tx):
                print("✓ Challenge is valid and matches transaction data")
            else:
                print("✗ Challenge does not match transaction data", file=sys.stderr)
                sys.exit(1)

    except ChallengeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Error: File not found: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
