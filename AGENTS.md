# Repository Guidelines

## Instruction Files

Read these before making changes; they are authoritative for repo workflows.

| Topic              | File                                                               |
| ------------------ | ------------------------------------------------------------------ |
| Agent instructions | [.github/copilot-instructions.md](.github/copilot-instructions.md) |
| Documentation      | [README.md](README.md)                                             |
| Docs               | [docs/README.md](docs/README.md)                                   |

## Project Structure

```
src/
├── python/
│   ├── harbour/        # Crypto library (sign, verify, keys, sd-jwt, kb-jwt, x509)
│   └── credentials/    # LinkML generation pipeline
└── typescript/
    └── harbour/        # TypeScript port of crypto library

tests/
├── fixtures/           # Shared test fixtures (credentials, keys, tokens)
├── interop/            # Cross-runtime interoperability tests
├── python/
│   ├── harbour/        # Python harbour module tests
│   └── credentials/    # Python credentials module tests
└── typescript/harbour/ # TypeScript harbour module tests
```

## Build, Test, and Development Commands

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

# Lint and format
make lint
make format

# Build TypeScript
make build-ts
```

## Git Commit & Pull Request Policy

### Commit Requirements

- **Always sign commits** with `-s -S` flags (Signed-off-by + GPG signature)
- **Never include AI attribution** in commits — no `Co-Authored-By`, `Generated-By`, or similar headers mentioning AI assistants (Claude, Copilot, ChatGPT, etc.)
- **Never mention AI tools in commit messages** — do not reference that code was AI-generated or AI-assisted
- **Author must be a human developer** with their official email address
- **Use conventional commit format**: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`

```bash
# Correct commit command
git commit -s -S -m "feat(harbour): add KB-JWT verification"
```

### Preparing Commits and Pull Requests

When instructed to prepare a commit or PR, **do not commit directly**. Instead:

1. Create the `.playground/` directory (already in `.gitignore`)
2. Generate two markdown files:
   - `.playground/commit-message.md` — Conventional commit message(s)
   - `.playground/pr-description.md` — PR description following the repository's PR template

The human operator will review these files and either:
- Use them to manually commit/push and create a PR, or
- Use automated tooling with signed commits (`git commit -s -S`)

### Commit Message Format

```markdown
# .playground/commit-message.md

feat(harbour): add KB-JWT support

- Implement createKbJwt() for holder binding
- Add verifyKbJwt() with nonce and audience validation
- Port from Python implementation

Refs: #42
```

### PR Description Format

Follow `.github/pull_request_template.md` if it exists, otherwise use:

```markdown
# .playground/pr-description.md

## Summary

Brief description of the changes.

## Changes

- List of specific changes made
- Another change

## Testing

- [ ] Python tests pass (`make test`)
- [ ] TypeScript tests pass (`make test-ts`)
- [ ] All tests pass (`make test-all`)

## Related Issues

Closes #42
```

## Coding Style

### Python
- Python 3.10+ with type hints on public APIs
- Use `pathlib.Path` (not `os.path`)
- 4-space indentation
- CLI modules must have `main()` with `argparse` and `--help`
- Run `make lint` before committing

### TypeScript
- TypeScript 5.x with strict mode
- Use async/await for crypto operations
- Export types alongside functions
- Run `npm run lint` before committing

## Module CLI Requirements

All Python modules under `harbour/` and `credentials/` must have:

```python
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Module description"
    )
    # Add arguments...
    args = parser.parse_args()
    # Implementation...

if __name__ == "__main__":
    main()
```

This enables `python -m harbour.keys --help` for all modules.
