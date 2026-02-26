# Contributing to Harbour Credentials

Thank you for your interest in contributing to Harbour Credentials!

## Getting Started

1. **Fork and clone** the repository:

   ```bash
   git clone --recurse-submodules https://github.com/YOUR_USERNAME/harbour-credentials.git
   cd harbour-credentials
   ```

2. **Set up the development environment**:

   ```bash
   make setup
   source .venv/bin/activate
   ```

3. **Verify everything works**:

   ```bash
   make test-all
   make lint
   ```

## Development Workflow

### Branching

- Create feature branches from `main`
- Use descriptive branch names: `feat/add-kb-jwt-support`, `fix/sd-jwt-verification`

### Making Changes

1. **Python code** lives in `src/python/harbour/` and `src/python/credentials/`
2. **TypeScript code** lives in `src/typescript/harbour/`
3. **Tests** live in `tests/` (see structure in README)
4. **Documentation** lives in `docs/`

### Code Style

#### Python

- Python 3.12+ with type hints on public APIs
- Use `pathlib.Path` (not `os.path`)
- All modules must have `main()` with `argparse` and `--help`
- Run `make lint` and `make format` before committing

#### TypeScript

- TypeScript 5.x with strict mode
- Use `async/await` for crypto operations
- Export types alongside functions
- Run `make lint-ts` before committing

### Testing

```bash
# Run all tests
make test-all

# Python only
make test

# TypeScript only
make test-ts

# Single Python test file
PYTHONPATH=src/python:$PYTHONPATH pytest tests/python/harbour/test_keys.py -v

# Single TypeScript test
cd src/typescript/harbour && yarn vitest run --config vitest.config.ts ../../../tests/typescript/harbour/keys.test.ts
```

### Feature Parity

When adding features, implement in **both** Python and TypeScript to maintain feature parity. Use consistent API naming:

| Python (snake_case) | TypeScript (camelCase) |
|---------------------|------------------------|
| `generate_p256_keypair()` | `generateP256Keypair()` |
| `sign_vc_jose()` | `signVcJose()` |
| `verify_sd_jwt_vc()` | `verifySdJwtVc()` |

## Commit Guidelines

### Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(harbour): add KB-JWT verification
fix(sd-jwt): handle empty disclosure arrays
docs: update quickstart guide
test(interop): add cross-runtime signing test
chore: update dependencies
```

### Signing Commits

All commits must be signed:

```bash
git commit -s -S -m "feat(harbour): add feature"
```

- `-s` adds `Signed-off-by` line (DCO)
- `-S` adds GPG signature

## Pull Requests

### Before Submitting

- [ ] All tests pass (`make test-all`)
- [ ] Linting passes (`make lint`)
- [ ] Documentation is updated if needed
- [ ] Commit messages follow conventional format
- [ ] Commits are signed (`-s -S`)

### PR Description

Include:

- **Summary** of the changes
- **Testing** performed
- **Related issues** (e.g., `Closes #42`)

## Architecture Decisions

Major design decisions are documented in Architecture Decision Records (ADRs):

- [ADR-001: VC Securing Mechanism](decisions/001-vc-securing-mechanism.md)
- [ADR-002: Dual Runtime Architecture](decisions/002-dual-runtime-architecture.md)
- [ADR-003: Canonicalization](decisions/003-canonicalization.md)
- [ADR-004: Key Management](decisions/004-key-management.md)

When proposing significant changes, consider creating a new ADR.

## Reporting Issues

- **Bugs**: Include steps to reproduce, expected vs actual behavior, and environment details
- **Features**: Describe the use case and proposed solution
- **Security**: Report security vulnerabilities privately (do not create public issues)

## Code of Conduct

Be respectful and inclusive. We welcome contributors of all backgrounds and experience levels.

## License

By contributing, you agree that your contributions will be licensed under the EPL-2.0 License.
