# encrypted_cache

Encrypt and cache plist-serializable data on disk with TTL-based invalidation.

**Module:** `encrypted_cache`
**Spec:** `spec/rfeat-010-encrypted_cache.md`

## Installation

```bash
uv pip install -e .
# or
pip install -e .
```

## Quick start

```python
from encrypted_cache import EncryptedCache

secrets = {"api": "my-secret-password"}
cache = EncryptedCache(secrets, salt=b"my-application-salt")

def fetch_from_api():
    return {"price": 42.0, "currency": "EUR"}

result = cache.execute_cached("api", fetch_from_api, "prices/latest", ttl="1 day")
print(result)  # {"price": 42.0, "currency": "EUR"}
```

On the first call the callback runs and the result is encrypted to disk.
Subsequent calls return the cached value until the TTL expires.

## API reference

### `get_hashed_filename(text, length=32, prefix=None)`

Derive a filesystem-safe hex string from arbitrary text (SHA-256).

```python
from encrypted_cache import get_hashed_filename

cache_id = get_hashed_filename("get_prices(date=2026-02-07)", prefix="prices")
# e.g. "prices-a1b2c3d4..."
```

### `EncryptedCache(secrets, salt, ...)`

| Parameter | Default | Description |
|---|---|---|
| `secrets` | *required* | `dict[str, str]` — logical key names to passwords. |
| `salt` | *required* | `bytes` — shared salt for key derivation. |
| `suffix` | `".enc.json"` | File extension for envelope files. |
| `cache_base_directory` | auto | Root directory. Defaults to `<project>/data/encryptedcache`. |
| `ttl` | `"5 days"` | Default TTL for `execute_cached`. |

### `cache.save(filepath, data, key_name="default", ...)`

Encrypt raw `bytes` and write a JSON envelope to disk.  Returns the
normalised `Path`.

### `cache.load(filepath)` / `cache.load_entry(filepath)`

Decrypt and return the payload.  `load_entry` additionally returns a
metadata dict with `key`, `created_at`, `comment`, and `validasof_datetime`.

### `cache.exists(filepath)`

Check whether the envelope file exists on disk.

### `cache.execute_cached(key_name, callback, cache_id, ...)`

Cache-or-compute pattern.  Key parameters:

| Parameter | Description |
|---|---|
| `key_name` | Which secret to use for encryption. |
| `callback` | Zero-argument callable returning plist-serializable data. |
| `cache_id` | Relative path used as cache key (e.g. `"api/prices"`). |
| `rerun` | `True` to force re-execution. |
| `ttl` | Override instance default. Accepts `"5 days"`, `"infinite"`, `datetime`, `0`, or `None` (infinite). When omitted, the instance default TTL is used. |
| `oldest_valid_cache_dt` | Optional `datetime`.  Cache entries created before this timestamp are treated as stale, regardless of TTL.  Useful when the upstream data source has a known last-update time. |

## TTL formats

| Value | Meaning |
|---|---|
| `"5 days"`, `"3d 2h 30m"` | Duration relative to creation time. |
| `"infinite"` / `"inf"` / `"forever"` | Never expires. |
| `None` | Same as infinite. |
| `0` | Always stale — forces re-execution. |
| `datetime` (tz-aware) | Absolute expiry timestamp. |
| ISO-8601 string | Parsed as absolute expiry. |

## File layout

Cache files are JSON envelopes written with restrictive permissions:

- Directories: `0o700` (user-only)
- Files: `0o600` (user-only)

```
data/encryptedcache/
  api_response.enc.json
  prices-a1b2c3d4e5f6...enc.json
```

Envelope structure (cleartext metadata, encrypted payload):

```json
{
  "key": "api",
  "salt_sha256": "a1b2c3d4e5f6g7h8",
  "created_at": "2026-02-07T12:00:00+00:00",
  "comment": "daily refresh",
  "encrypted": "<Fernet token>"
}
```

The encrypted payload is a binary plist containing `data` (raw bytes) and
optional `validasof_datetime`.

## Salt rotation

Changing the salt invalidates all existing cache files.  `execute_cached`
handles this transparently: a `SaltMismatchError` is caught and the
callback is re-executed.  Direct `load` / `load_entry` calls will raise
`SaltMismatchError` so the caller can decide how to proceed.

## Running tests

```bash
uv run pytest tests/test_rfeat_010_encrypted_cache.py -v
```
