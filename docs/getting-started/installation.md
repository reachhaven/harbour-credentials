# Installation

## Python

### From PyPI (when published)

```bash
pip install harbour-credentials
```

### From Source

```bash
git clone https://github.com/ASCS-eV/harbour-credentials.git
cd harbour-credentials

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"
```

### Development Setup

```bash
make setup
make install-dev
```

## TypeScript

### From npm (when published)

```bash
npm install @reachhaven/harbour-credentials
```

### From Source

```bash
git clone https://github.com/ASCS-eV/harbour-credentials.git
cd harbour-credentials/src/typescript/harbour

npm install
npm run build
```

## Verify Installation

=== "Python"

    ```bash
    python -m harbour.keys --help
    make test
    ```

=== "TypeScript"

    ```bash
    npm test
    ```

## Dependencies

### Python

- `cryptography` — Cryptographic primitives
- `joserfc` — JOSE/JWT implementation
- `sd-jwt` — SD-JWT implementation

### TypeScript

- `jose` — JOSE/JWT implementation
- `@sd-jwt/core` — SD-JWT implementation
