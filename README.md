# encrypted-cache

A Python library for password-based encrypted local caching with TTL-aware cache-or-compute pattern.

Uses Fernet (AES-128-CBC + HMAC-SHA256) with PBKDF2-HMAC-SHA256 key derivation and cleartext metadata envelopes for TTL-based cache invalidation.

> N.B.: **After cloning**, enable the pre-push secret scanner: `git config core.hooksPath .githooks`
> This scans pushed commits for accidental secret and bank identifier leaks (IBAN/ISIN).

Example usage:
```python
from encrypted_cache import EncryptedCache

cache = EncryptedCache({"api": "example-password"}, salt=b"example-salt")

def fetch_prices():
    return {"value": 42}

result = cache.execute_cached("api", fetch_prices, "prices/latest", ttl="1 day")
```

IMPORTANT: If your notebook outputs any sensitive date, make certain that nbstripout has been installed as a commit hook in git so that these secrets do not get archived in git (it is enabled by default in this repo and should also be active for clones, but please double-check)

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

### Optional: Pre-push secret scan

```bash
git config core.hooksPath .githooks
```

This uses `scripts/pre-push-secret-scan.sh` to scan added lines in commits being pushed for common secret patterns and bank identifiers (IBAN/ISIN). To bypass once, run `SECRET_SCAN_ALLOW=1 git push`.

## License

Apache 2.0 — see [LICENSE](LICENSE).
