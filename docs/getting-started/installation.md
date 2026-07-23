# Installation

## Python

### From PyPI (when published)

```bash
pip install harbour-credentials
```

### From Source (development)

Requires [uv](https://docs.astral.sh/uv/) and [just](https://just.systems) on
your PATH (plus Node.js 22 with Corepack for the TypeScript recipes):

```bash
git clone https://github.com/reachhaven/harbour-credentials.git
cd harbour-credentials

# Set up the full dev environment: flat submodules + uv sync (deps, LinkML fork,
# editable omb) + pre-commit hooks + TypeScript deps.
just setup
```

`just` recipes run through `uv run`, which creates and syncs an isolated `.venv`
from `uv.lock` on demand — no manual venv creation or activation is needed. Use
`just install-dev` to re-sync only the Python environment. Activate the venv only
for direct `python`/`pip` commands:

```bash
# PowerShell
.\.venv\Scripts\Activate.ps1

# macOS / Linux / Git Bash
source .venv/bin/activate
```

## TypeScript

### From npm (when published)

```bash
npm install @reachhaven/harbour-credentials
```

### From Source

```bash
git clone https://github.com/reachhaven/harbour-credentials.git
cd harbour-credentials/src/typescript/harbour

corepack yarn install
corepack yarn build
```

## Verify Installation

**Python:**

```bash
python -m harbour.keys --help
just test
```

**TypeScript:**

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
