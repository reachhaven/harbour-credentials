"""Cross-runtime interop tests: Python signs → Node.js verifies (and vice versa)."""

import json
import subprocess
from pathlib import Path

import pytest

from harbour.jose.keys import p256_public_key_to_did_key
from harbour.jose.signer import sign_vc_jose, sign_vp_jose
from harbour.jose.verifier import verify_vc_jose, verify_vp_jose

FIXTURES_DIR = Path(__file__).parent / "fixtures"
JS_DIR = Path(__file__).parent.parent / "js"

# Skip if node_modules not installed
pytestmark = pytest.mark.skipif(
    not (JS_DIR / "node_modules").exists(),
    reason="JS dependencies not installed (run 'npm install' in js/)",
)


def _run_node(script: str) -> str:
    """Run a Node.js script and return its stdout."""
    result = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
        cwd=str(JS_DIR),
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Node.js error:\n{result.stderr}")
    return result.stdout.strip()


class TestPythonSignNodeVerify:
    """Python signs a VC/VP → Node.js verifies it."""

    def test_vc_jose(self, sample_vc, p256_private_key, p256_public_key):
        token = sign_vc_jose(sample_vc, p256_private_key)
        fixture = json.loads((FIXTURES_DIR / "test-keypair-p256.json").read_text())
        pub_jwk = {"kty": fixture["kty"], "crv": fixture["crv"],
                    "x": fixture["x"], "y": fixture["y"]}

        script = f"""
import {{ compactVerify, importJWK }} from "jose";
const pubJwk = {json.dumps(pub_jwk)};
const key = await importJWK(pubJwk, "ES256");
const result = await compactVerify("{token}", key);
const payload = JSON.parse(new TextDecoder().decode(result.payload));
console.log(JSON.stringify(payload));
"""
        output = _run_node(script)
        verified_vc = json.loads(output)
        assert verified_vc == sample_vc

    def test_vp_jose(self, sample_vp, p256_private_key):
        token = sign_vp_jose(
            sample_vp, p256_private_key,
            nonce="interop-nonce", audience="did:web:verifier.test"
        )
        fixture = json.loads((FIXTURES_DIR / "test-keypair-p256.json").read_text())
        pub_jwk = {"kty": fixture["kty"], "crv": fixture["crv"],
                    "x": fixture["x"], "y": fixture["y"]}

        script = f"""
import {{ compactVerify, importJWK }} from "jose";
const key = await importJWK({json.dumps(pub_jwk)}, "ES256");
const result = await compactVerify("{token}", key);
const payload = JSON.parse(new TextDecoder().decode(result.payload));
if (payload.nonce !== "interop-nonce") throw new Error("nonce mismatch");
if (payload.aud !== "did:web:verifier.test") throw new Error("aud mismatch");
console.log("OK");
"""
        assert _run_node(script) == "OK"


class TestNodeSignPythonVerify:
    """Node.js signs a VC/VP → Python verifies it."""

    def test_vc_jose(self, p256_public_key):
        fixture = json.loads((FIXTURES_DIR / "test-keypair-p256.json").read_text())
        sample_vc = json.loads((FIXTURES_DIR / "sample-vc.json").read_text())

        script = f"""
import {{ CompactSign, importJWK }} from "jose";
const jwk = {json.dumps(fixture)};
const key = await importJWK(jwk, "ES256");
const payload = new TextEncoder().encode(JSON.stringify({json.dumps(sample_vc)}));
const signer = new CompactSign(payload);
signer.setProtectedHeader({{ alg: "ES256", typ: "vc+ld+jwt" }});
const token = await signer.sign(key);
console.log(token);
"""
        token = _run_node(script)
        result = verify_vc_jose(token, p256_public_key)
        assert result == sample_vc

    def test_vp_jose(self, p256_public_key):
        fixture = json.loads((FIXTURES_DIR / "test-keypair-p256.json").read_text())

        vp = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [],
            "nonce": "cross-nonce",
            "aud": "did:web:verifier.test",
        }

        script = f"""
import {{ CompactSign, importJWK }} from "jose";
const jwk = {json.dumps(fixture)};
const key = await importJWK(jwk, "ES256");
const payload = new TextEncoder().encode(JSON.stringify({json.dumps(vp)}));
const signer = new CompactSign(payload);
signer.setProtectedHeader({{ alg: "ES256", typ: "vp+ld+jwt" }});
const token = await signer.sign(key);
console.log(token);
"""
        token = _run_node(script)
        result = verify_vp_jose(
            token, p256_public_key,
            expected_nonce="cross-nonce",
            expected_audience="did:web:verifier.test",
        )
        assert result["type"] == ["VerifiablePresentation"]
