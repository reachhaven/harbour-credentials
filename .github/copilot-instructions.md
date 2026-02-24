# Harbour Credentials - AI Assistant Instructions

This repository contains cryptographic libraries for signing and verifying verifiable credentials (Python + TypeScript).

## Build, Test, and Lint Commands

```bash
# Install dev dependencies
make setup
make install-dev

# Run all tests (Python + TypeScript)
make test-all

# Run Python tests only
make test

# Run TypeScript tests only
make test-ts

# Build TypeScript
make build-ts

# Lint and format
make lint
make format

# Run with coverage
make test-cov
```

## Instruction Files

Read these BEFORE making changes:

| Topic              | File                                      |
| ------------------ | ----------------------------------------- |
| Agent instructions | [AGENTS.md](../AGENTS.md)                 |
| Claude guidance    | [CLAUDE.md](../CLAUDE.md)                 |
| Documentation      | [README.md](../README.md)                 |
| Architecture       | [architecture.md](../docs/architecture.md)|

## Core Principles

1. **Dual Runtime**: Python and TypeScript implementations with feature parity
2. **CLI Required**: All Python modules must have `main()` with `argparse` and `--help`
3. **Type Safety**: Full type hints (Python) and strict mode (TypeScript)

## Project Structure

```
src/
├── python/
│   ├── harbour/        # Crypto library (keys, sign, verify, sd-jwt, kb-jwt, x509)
│   └── credentials/    # Credential processing pipeline
└── typescript/
    └── harbour/        # TypeScript port of crypto library

tests/
├── fixtures/           # Shared test fixtures (credentials, keys, tokens)
├── interop/            # Cross-runtime interoperability tests
├── python/
│   ├── harbour/        # Harbour Python tests
│   └── credentials/    # Credentials Python tests
└── typescript/harbour/ # Harbour TypeScript tests
```

## Key Conventions

- **Python**: Use `pathlib.Path`, type hints, `argparse` CLI with `--help`
- **TypeScript**: Use `async/await`, strict mode, export types with functions
- **Both**: Consistent API naming between runtimes
- **Tests**: Cover happy path, edge cases, and error cases

## CLI Module Template

All Python modules must follow this pattern:

```python
def main() -> None:
    parser = argparse.ArgumentParser(description="Module description")
    # Add arguments...
    args = parser.parse_args()
    # Implementation...

if __name__ == "__main__":
    main()
```

## Git Commit Policy

**STRICT REQUIREMENTS:**

- ✅ **Always sign commits** with `-s -S` flags (Signed-off-by + GPG signature)
- ❌ **Never include AI attribution** — no `Co-Authored-By`, `Generated-By`, or similar headers mentioning AI assistants (Claude, Copilot, ChatGPT, etc.)
- ❌ **Never mention AI tools in commit messages** — do not reference that code was AI-generated or AI-assisted
- ✅ **Author must be the human developer** — use official company email

```bash
# Correct commit command
git commit -s -S -m "feat(harbour): add KB-JWT support"
```

## Preparing Commits and Pull Requests

When instructed to prepare a commit or PR, **do not commit directly**. Instead:

1. Create files in the `.playground/` directory (already in `.gitignore`)
2. Generate two markdown files:
   - `.playground/commit-message.md` — Conventional commit message(s)
   - `.playground/pr-description.md` — PR description

The human operator will review these files and either:

- Use them to manually commit/push and create a PR, or
- Use automated tooling with signed commits (`git commit -s -S`)

## Common Mistakes to Avoid

- ❌ **Don't use `os.path`** — Use `pathlib.Path` instead
- ❌ **Don't forget CLI** — All Python modules need `main()` with `--help`
- ❌ **Don't break parity** — Keep Python and TypeScript APIs consistent
- ❌ **Don't commit without signing** — Always use `-s -S`
- ❌ **Don't skip tests** — Run `make test-all` before committing
