# encrypted-cache

A Python library for password-based encrypted local caching with TTL-aware cache-or-compute pattern.

Uses Fernet (AES-128-CBC + HMAC-SHA256) with PBKDF2-HMAC-SHA256 key derivation and cleartext metadata envelopes for TTL-based cache invalidation.

IMPORTANT: If your notebook should output any sensitive date, make certain to install nbstripout as a commit hook in git so that these secrets do not get archived in git

See [doc/encrypted_cache.md](doc/encrypted_cache.md) for full API documentation.

## Requirements

- Python >= 3.12

## Installation

```bash
# with uv
uv pip install -e .

# with pip
pip install -e .
```

## Development

```bash
uv pip install -e ".[dev]"
uv run pytest
uv run mypy src/encrypted_cache/
uv run ruff check src/ tests/
```

## License

MIT — see [LICENSE](LICENSE).
