"""Claim mappings from W3C VCDM JSON-LD to SD-JWT-VC flat claims.

Defines how each SimpulseID credential type maps between nested JSON-LD
(credentialSubject) and flat SD-JWT-VC claims, plus which claims are
selectively disclosable.

CLI Usage:
    python -m credentials.claim_mapping --help
    python -m credentials.claim_mapping to-sd-jwt --input vc.json --output claims.json
    python -m credentials.claim_mapping from-sd-jwt --input claims.json --type ParticipantCredential
"""

import argparse
import json
import sys
from pathlib import Path

VCT_BASE = "https://w3id.org/ascs-ev/simpulse-id/credentials/v1"

PARTICIPANT_MAPPING = {
    "vct": f"{VCT_BASE}/ParticipantCredential",
    "claims": {
        "credentialSubject.legalName": "legalName",
        "credentialSubject.legalForm": "legalForm",
        "credentialSubject.duns": "duns",
        "credentialSubject.email": "email",
        "credentialSubject.url": "url",
        "credentialSubject.legalAddress": "legalAddress",
        "credentialSubject.headquartersAddress": "headquartersAddress",
        "credentialSubject.registrationNumber": "registrationNumber",
        "credentialSubject.termsAndConditions": "termsAndConditions",
    },
    "always_disclosed": ["iss", "vct", "iat", "exp", "legalName", "legalForm"],
    "selectively_disclosed": [
        "legalAddress",
        "headquartersAddress",
        "registrationNumber",
        "email",
        "url",
        "duns",
    ],
}

ADMINISTRATOR_MAPPING = {
    "vct": f"{VCT_BASE}/AdministratorCredential",
    "claims": {
        "credentialSubject.givenName": "givenName",
        "credentialSubject.familyName": "familyName",
        "credentialSubject.email": "email",
        "credentialSubject.memberOf": "memberOf",
        "credentialSubject.address": "address",
        "credentialSubject.termsAndConditions": "termsAndConditions",
    },
    "always_disclosed": ["iss", "vct", "iat", "exp", "memberOf"],
    "selectively_disclosed": [
        "givenName",
        "familyName",
        "email",
        "address",
    ],
}

USER_MAPPING = {
    "vct": f"{VCT_BASE}/UserCredential",
    "claims": {
        "credentialSubject.givenName": "givenName",
        "credentialSubject.familyName": "familyName",
        "credentialSubject.email": "email",
        "credentialSubject.memberOf": "memberOf",
        "credentialSubject.termsAndConditions": "termsAndConditions",
    },
    "always_disclosed": ["iss", "vct", "iat", "exp", "memberOf"],
    "selectively_disclosed": [
        "givenName",
        "familyName",
        "email",
    ],
}

BASE_MEMBERSHIP_MAPPING = {
    "vct": f"{VCT_BASE}/AscsBaseMembershipCredential",
    "claims": {
        "credentialSubject.memberOf": "memberOf",
        "credentialSubject.programName": "programName",
        "credentialSubject.hostingOrganization": "hostingOrganization",
        "credentialSubject.memberSince": "memberSince",
        "credentialSubject.termsAndConditions": "termsAndConditions",
    },
    "always_disclosed": [
        "iss",
        "vct",
        "iat",
        "exp",
        "memberOf",
        "programName",
    ],
    "selectively_disclosed": ["memberSince", "hostingOrganization"],
}

ENVITED_MEMBERSHIP_MAPPING = {
    "vct": f"{VCT_BASE}/AscsEnvitedMembershipCredential",
    "claims": {
        "credentialSubject.memberOf": "memberOf",
        "credentialSubject.programName": "programName",
        "credentialSubject.hostingOrganization": "hostingOrganization",
        "credentialSubject.memberSince": "memberSince",
        "credentialSubject.baseMembershipCredential": "baseMembershipCredential",
        "credentialSubject.termsAndConditions": "termsAndConditions",
    },
    "always_disclosed": [
        "iss",
        "vct",
        "iat",
        "exp",
        "memberOf",
        "programName",
        "baseMembershipCredential",
    ],
    "selectively_disclosed": ["memberSince", "hostingOrganization"],
}

# Registry: VC type string → mapping dict
MAPPINGS = {
    "simpulseid:ParticipantCredential": PARTICIPANT_MAPPING,
    "simpulseid:AdministratorCredential": ADMINISTRATOR_MAPPING,
    "simpulseid:UserCredential": USER_MAPPING,
    "simpulseid:AscsBaseMembershipCredential": BASE_MEMBERSHIP_MAPPING,
    "simpulseid:AscsEnvitedMembershipCredential": ENVITED_MEMBERSHIP_MAPPING,
}


def vc_to_sd_jwt_claims(vc: dict, mapping: dict) -> tuple[dict, list[str]]:
    """Convert a W3C VCDM JSON-LD VC to flat SD-JWT-VC claims.

    Args:
        vc: The Verifiable Credential JSON-LD dict.
        mapping: One of the *_MAPPING dicts above.

    Returns:
        Tuple of (flat_claims_dict, disclosable_claim_names).
    """
    claims = {}

    # Map issuer
    issuer = vc.get("issuer")
    if isinstance(issuer, dict):
        claims["iss"] = issuer.get("id", "")
    elif isinstance(issuer, str):
        claims["iss"] = issuer

    # Map subject ID
    subject = vc.get("credentialSubject", {})
    claims["sub"] = subject.get("id", "")

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
        mapping: One of the *_MAPPING dicts above.
        vc_type: The VC type (e.g., "simpulseid:ParticipantCredential").

    Returns:
        W3C VCDM JSON-LD dict.
    """
    vc: dict = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://w3id.org/ascs-ev/simpulse-id/credentials/v1/",
            "https://w3id.org/reachhaven/harbour/credentials/v1/",
            "https://w3id.org/gaia-x/development/",
        ],
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
    """Find the matching mapping for a VC based on its type."""
    vc_types = vc.get("type", [])
    for vc_type, mapping in MAPPINGS.items():
        if vc_type in vc_types:
            return mapping
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_nested(obj: dict, path: str):
    """Get a nested value by dot-separated path."""
    parts = path.split(".")
    current = obj
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _set_nested(obj: dict, path: str, value):
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


def main():
    """CLI entry point for claim mapping."""
    parser = argparse.ArgumentParser(
        prog="credentials.claim_mapping",
        description="Convert between W3C VCDM and SD-JWT-VC claim formats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m credentials.claim_mapping to-sd-jwt --input vc.json
  python -m credentials.claim_mapping from-sd-jwt --input claims.json --type ParticipantCredential
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
        "--type", "-t", required=True, help="VC type (e.g., ParticipantCredential)"
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
        vc_type = f"simpulseid:{args.type}"
        mapping = MAPPINGS.get(vc_type)
        if mapping is None:
            print(f"Unknown VC type: {args.type}", file=sys.stderr)
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
