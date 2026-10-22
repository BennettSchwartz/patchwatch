[← Patchwatch](../README.md)

# Development

```sh
uv sync --locked --extra dev
uv run ruff check src tests
uv run ruff format --check src tests
uv run pytest
uv run patchwatch catalog validate src/patchwatch/data/catalog.json
uv build
```

Tests include a real offline wheel update and rollback in a disposable virtual environment. The OSV/catalog HTTP boundaries are mocked in unit tests; live integration is checked separately.

See [Contributing advisories](../CONTRIBUTING.md) for catalog changes.
