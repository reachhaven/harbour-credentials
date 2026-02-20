# CLI Reference

Harbour Credentials provides CLI tools for all major operations. Each Python module under `harbour/` has a `main()` function with `--help`.

## Available Commands

| Command | Description |
|---------|-------------|
| `python -m harbour.keys` | Key generation and conversion |
| `python -m harbour.signer` | Sign credentials |
| `python -m harbour.verifier` | Verify signed credentials |
| `python -m harbour.sd_jwt` | SD-JWT operations |
| `python -m harbour.kb_jwt` | Key Binding JWT |
| `python -m harbour.x509` | X.509 certificate operations |

## Quick Examples

```bash
# Generate a P-256 keypair
python -m harbour.keys generate --curve p256 --output keypair.json

# Sign a credential
python -m harbour.signer sign --input credential.json --key keypair.json --output signed.jwt

# Verify a signed credential
python -m harbour.verifier verify --input signed.jwt --key public-key.json

# Issue SD-JWT with selective disclosure
python -m harbour.sd_jwt issue --input credential.json --key keypair.json --disclose name email

# Verify SD-JWT
python -m harbour.sd_jwt verify --input credential.sd-jwt --key public-key.json
```

## Getting Help

Each command supports `--help`:

```bash
python -m harbour.keys --help
python -m harbour.signer --help
python -m harbour.sd_jwt --help
```
