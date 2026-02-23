"""Credentials pipeline - credential processing and claim mapping.

This package provides tools for:
- Mapping between W3C VCDM and SD-JWT-VC claim formats
- Signing example credentials for testing and documentation

Usage:
    python -m credentials.claim_mapping --help
    python -m credentials.example_signer --help
"""

from credentials.claim_mapping import (
    MAPPINGS,
    get_mapping_for_vc,
    sd_jwt_claims_to_vc,
    vc_to_sd_jwt_claims,
)

__all__ = [
    "MAPPINGS",
    "vc_to_sd_jwt_claims",
    "sd_jwt_claims_to_vc",
    "get_mapping_for_vc",
]
