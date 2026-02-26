"""Generic claim mappings from W3C VCDM JSON-LD to SD-JWT-VC flat claims.

Provides a framework for mapping between nested JSON-LD (credentialSubject)
and flat SD-JWT-VC claims, plus which claims are selectively disclosable.

This module provides the core mapping functions. Domain-specific mappings
(e.g., Gaia-X, organizational credentials) can register their own mappings.

CLI Usage:
    python -m credentials.claim_mapping --help
    python -m credentials.claim_mapping to-sd-jwt --input vc.json --mapping mapping.json
    python -m credentials.claim_mapping from-sd-jwt --input claims.json --mapping mapping.json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Harbour Credential Mappings
# ---------------------------------------------------------------------------

# Harbour namespace
HARBOUR_NS = "https://w3id.org/reachhaven/harbour/credentials/v1/"

# Gaia-X namespace
GAIAX_NS = "https://w3id.org/gaia-x/development#"

HARBOUR_LEGAL_PERSON_MAPPING = {
    "vct": f"{HARBOUR_NS}LegalPersonCredential",
    "claims": {
        "credentialSubject.name": "name",
        "credentialSubject.gxParticipant.schema:name": "legalName",
        "credentialSubject.gxParticipant.gx:registrationNumber": "registrationNumber",
        "credentialSubject.gxParticipant.gx:headquartersAddress": "headquartersAddress",
        "credentialSubject.gxParticipant.gx:legalAddress": "legalAddress",
    },
    "always_disclosed": ["iss", "vct", "iat", "exp", "name", "legalName"],
    "selectively_disclosed": [
        "registrationNumber",
        "headquartersAddress",
        "legalAddress",
    ],
}

HARBOUR_NATURAL_PERSON_MAPPING = {
    "vct": f"{HARBOUR_NS}NaturalPersonCredential",
    "claims": {
        "credentialSubject.schema:givenName": "givenName",
        "credentialSubject.schema:familyName": "familyName",
        "credentialSubject.schema:email": "email",
        "credentialSubject.memberOf": "memberOf",
    },
    "always_disclosed": ["iss", "vct", "iat", "exp"],
    "selectively_disclosed": ["givenName", "familyName", "email", "memberOf"],
}

HARBOUR_SERVICE_OFFERING_MAPPING = {
    "vct": f"{HARBOUR_NS}ServiceOfferingCredential",
    "claims": {
        "credentialSubject.name": "name",
        "credentialSubject.description": "description",
        "credentialSubject.gxServiceOffering.gx:providedBy": "providedBy",
        "credentialSubject.gxServiceOffering.gx:serviceOfferingTermsAndConditions": "termsAndConditions",
    },
    "always_disclosed": ["iss", "vct", "iat", "exp", "providedBy", "name"],
    "selectively_disclosed": ["description", "termsAndConditions"],
}

# Registry: VC type string → mapping dict
# Additional mappings can be registered at runtime
MAPPINGS: dict[str, dict] = {
    "harbour:LegalPersonCredential": HARBOUR_LEGAL_PERSON_MAPPING,
    "harbour:NaturalPersonCredential": HARBOUR_NATURAL_PERSON_MAPPING,
    "harbour:ServiceOfferingCredential": HARBOUR_SERVICE_OFFERING_MAPPING,
}


def register_mapping(vc_type: str, mapping: dict) -> None:
    """Register a custom credential type mapping.

    Args:
        vc_type: The credential type name (e.g., "MyCustomCredential").
        mapping: Mapping dict with keys: vct, claims, always_disclosed, selectively_disclosed.
    """
    MAPPINGS[vc_type] = mapping


def vc_to_sd_jwt_claims(vc: dict, mapping: dict) -> tuple[dict, list[str]]:
    """Convert a JSON-LD object to flat SD-JWT-VC claims.

    Supports both:
    - W3C VCDM format (with credentialSubject)
    - Gaia-X flat format (with @id, @type at top level)

    Args:
        vc: The JSON-LD dict (VC or Gaia-X object).
        mapping: Mapping dict with keys: vct, claims, always_disclosed, selectively_disclosed.

    Returns:
        Tuple of (flat_claims_dict, disclosable_claim_names).
    """
    claims: dict[str, Any] = {}

    # Map issuer (W3C VCDM style)
    issuer = vc.get("issuer")
    if isinstance(issuer, dict):
        claims["iss"] = issuer.get("id", "")
    elif isinstance(issuer, str):
        claims["iss"] = issuer

    # Map subject ID - support both W3C VCDM and Gaia-X flat format
    if "credentialSubject" in vc:
        subject = vc.get("credentialSubject", {})
        claims["sub"] = subject.get("id", "")
    elif "@id" in vc:
        # Gaia-X flat format: @id is the subject
        claims["sub"] = vc["@id"]

    # Map validity
    if "validFrom" in vc:
        claims["iat"] = vc["validFrom"]
    if "validUntil" in vc:
        claims["exp"] = vc["validUntil"]

    # Map credential-specific claims
    for vc_path, flat_name in mapping["claims"].items():
        value = _get_nested(vc, vc_path)
        if value is not None:
            claims[flat_name] = value

    disclosable = [
        name for name in mapping.get("selectively_disclosed", []) if name in claims
    ]

    return claims, disclosable


def sd_jwt_claims_to_vc(claims: dict, mapping: dict, vc_type: str) -> dict:
    """Convert flat SD-JWT-VC claims back to W3C VCDM JSON-LD structure.

    Args:
        claims: Flat claims dict.
        mapping: Mapping dict.
        vc_type: The VC type (e.g., "LegalParticipantCredential").

    Returns:
        W3C VCDM JSON-LD dict.
    """
    vc: dict = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", vc_type],
    }

    if "iss" in claims:
        vc["issuer"] = {"id": claims["iss"]}
    if "iat" in claims:
        vc["validFrom"] = claims["iat"]
    if "exp" in claims:
        vc["validUntil"] = claims["exp"]

    subject: dict = {}
    if "sub" in claims:
        subject["id"] = claims["sub"]

    # Reverse map
    reverse_map = {v: k for k, v in mapping["claims"].items()}
    for flat_name, value in claims.items():
        if flat_name in reverse_map:
            vc_path = reverse_map[flat_name]
            _set_nested(vc, vc_path, value)

    if subject or vc.get("credentialSubject"):
        existing = vc.get("credentialSubject", {})
        vc["credentialSubject"] = {**subject, **existing}

    return vc


def get_mapping_for_vc(vc: dict) -> dict | None:
    """Find the matching mapping for a VC based on its type.

    Supports both:
    - W3C VCDM: "type" array (e.g., ["VerifiableCredential", "PersonCredential"])
    - Gaia-X: "@type" string (e.g., "gx:LegalPerson")

    Args:
        vc: The JSON-LD dict.

    Returns:
        Matching mapping dict or None if not found.
    """
    # Get types from both W3C VCDM and JSON-LD formats
    vc_types = vc.get("type", [])
    if isinstance(vc_types, str):
        vc_types = [vc_types]

    # Also check @type for Gaia-X format
    at_type = vc.get("@type")
    if at_type:
        if isinstance(at_type, str):
            vc_types = vc_types + [at_type]
        elif isinstance(at_type, list):
            vc_types = vc_types + at_type

    for vc_type, mapping in MAPPINGS.items():
        if vc_type in vc_types:
            return mapping
    return None


def create_mapping(
    vct: str,
    claims: dict[str, str],
    always_disclosed: list[str] | None = None,
    selectively_disclosed: list[str] | None = None,
) -> dict:
    """Create a new mapping configuration.

    Args:
        vct: The SD-JWT-VC type URI.
        claims: Dict mapping JSON-LD paths to flat claim names.
        always_disclosed: Claim names that are always disclosed.
        selectively_disclosed: Claim names that can be selectively disclosed.

    Returns:
        Mapping dict ready for use with vc_to_sd_jwt_claims/sd_jwt_claims_to_vc.
    """
    return {
        "vct": vct,
        "claims": claims,
        "always_disclosed": always_disclosed or ["iss", "vct", "iat", "exp"],
        "selectively_disclosed": selectively_disclosed or [],
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_nested(obj: dict, path: str) -> Any:
    """Get a nested value by dot-separated path."""
    parts = path.split(".")
    current: Any = obj
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _set_nested(obj: dict, path: str, value: Any) -> None:
    """Set a nested value by dot-separated path."""
    parts = path.split(".")
    current = obj
    for part in parts[:-1]:
        if part not in current:
            current[part] = {}
        current = current[part]
    current[parts[-1]] = value


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point for claim mapping."""
    parser = argparse.ArgumentParser(
        prog="credentials.claim_mapping",
        description="Convert between W3C VCDM and SD-JWT-VC claim formats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m credentials.claim_mapping to-sd-jwt --input vc.json
  python -m credentials.claim_mapping from-sd-jwt --input claims.json --type PersonCredential
  python -m credentials.claim_mapping list-types
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # to-sd-jwt subcommand
    to_parser = subparsers.add_parser(
        "to-sd-jwt",
        help="Convert W3C VCDM credential to SD-JWT flat claims",
        description="Transform a W3C VCDM JSON-LD credential to flat SD-JWT claims.",
    )
    to_parser.add_argument("--input", "-i", required=True, help="Input VC JSON file")
    to_parser.add_argument("--output", "-o", help="Output file (default: stdout)")

    # from-sd-jwt subcommand
    from_parser = subparsers.add_parser(
        "from-sd-jwt",
        help="Convert SD-JWT flat claims to W3C VCDM format",
        description="Transform flat SD-JWT claims back to W3C VCDM JSON-LD format.",
    )
    from_parser.add_argument(
        "--input", "-i", required=True, help="Input claims JSON file"
    )
    from_parser.add_argument(
        "--type", "-t", required=True, help="VC type (e.g., PersonCredential)"
    )
    from_parser.add_argument("--output", "-o", help="Output file (default: stdout)")

    # list-types subcommand
    subparsers.add_parser(
        "list-types",
        help="List supported credential types",
        description="Show all credential types with registered mappings.",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "to-sd-jwt":
        vc = json.loads(Path(args.input).read_text())
        mapping = get_mapping_for_vc(vc)
        if mapping is None:
            print(f"No mapping found for VC types: {vc.get('type')}", file=sys.stderr)
            sys.exit(1)

        claims, disclosable = vc_to_sd_jwt_claims(vc, mapping)
        result = {
            "claims": claims,
            "disclosable": disclosable,
            "vct": mapping["vct"],
        }

        output = json.dumps(result, indent=2)
        if args.output:
            Path(args.output).write_text(output)
            print(f"Claims written to {args.output}", file=sys.stderr)
        else:
            print(output)

    elif args.command == "from-sd-jwt":
        data = json.loads(Path(args.input).read_text())
        claims = data.get("claims", data)  # Support both wrapped and raw claims
        vc_type = args.type
        mapping = MAPPINGS.get(vc_type)
        if mapping is None:
            print(f"Unknown VC type: {vc_type}", file=sys.stderr)
            print(f"Available: {', '.join(MAPPINGS.keys())}", file=sys.stderr)
            sys.exit(1)

        vc = sd_jwt_claims_to_vc(claims, mapping, vc_type)
        output = json.dumps(vc, indent=2)
        if args.output:
            Path(args.output).write_text(output)
            print(f"VC written to {args.output}", file=sys.stderr)
        else:
            print(output)

    elif args.command == "list-types":
        print("Supported credential types:")
        for type_key, mapping in MAPPINGS.items():
            print(f"  {type_key}")
            print(f"    vct: {mapping['vct']}")


if __name__ == "__main__":
    main()
