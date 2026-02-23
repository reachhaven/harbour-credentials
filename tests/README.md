# Test Suite Structure

This repository keeps tests grouped by runtime and module ownership.

## Layout

```text
tests/
├── fixtures/
│   ├── credentials/          # JSON credential fixtures
│   ├── keys/                 # Shared JWK fixtures
│   ├── tokens/               # Signed token fixtures
│   └── sample-vc.json        # Shared unsigned VC payload
├── interop/
│   └── test_cross_runtime.py # Python <-> Node interoperability checks
├── python/
│   ├── harbour/              # Tests for src/python/harbour/*
│   └── credentials/          # Tests for src/python/credentials/*
└── typescript/
    └── harbour/              # Tests for src/typescript/harbour/*
```

## Conventions

- Place new Python tests under `tests/python/<module>/`.
- Place cross-runtime tests only under `tests/interop/`.
- Reuse committed fixtures from `tests/fixtures/` instead of generating ad-hoc keys.
- Keep TypeScript tests under `tests/typescript/harbour/` to match Vitest include paths.
