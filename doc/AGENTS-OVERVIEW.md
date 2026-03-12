# encrypted_cache — Agent API Reference

`encrypted_cache` is a single-class Python library providing password-based encrypted
on-disk caching for plist-serializable data. Keys are derived from passwords via
PBKDF2-HMAC-SHA256; payloads are encrypted with Fernet and stored as JSON envelopes
containing cleartext metadata (creation timestamp, TTL, optional comment) alongside
the ciphertext. The primary usage pattern is `execute_cached()`, which implements
cache-or-compute: return a cached entry if it is fresh, otherwise call a callback,
encrypt the result, store it, and return it. TTL-based and timestamp-based
invalidation are both supported.

---

## Entry point

```python
from encrypted_cache import EncryptedCache, SaltMismatchError, get_hashed_filename

cache = EncryptedCache(
    secrets    = {"mykey": "my-password"},   # dict[name → password]
    salt       = "my-salt",                  # str or bytes; changing this invalidates all files
    suffix     = ".enc.json",                # file extension (default)
    cache_base_directory = "data/cache",     # None = auto-detect from pyproject.toml
    ttl        = "5 days",                   # default TTL; None = infinite
)
```

- `secrets` — mapping of logical key names to passwords. Multiple keys can be defined;
  each `save`/`load`/`execute_cached` call picks one by name.
- `salt` — shared salt for key derivation. Changing it makes previously written files
  unreadable (`SaltMismatchError`).
- `cache_base_directory` — defaults to `<project_root>/data/encryptedcache` (found by
  walking up to `pyproject.toml`), or `/tmp/encryptedcache-<uid>` as fallback.
- `ttl` — accepts a duration string (`"5 days"`, `"3d 2h"`), an absolute `datetime`,
  or `None` for infinite. Applied per-entry by `execute_cached` unless overridden.

---

## Common usage patterns

### Cache-or-compute (primary pattern)

```python
result = cache.execute_cached(
    key_name  = "mykey",
    callback  = lambda: expensive_computation(),   # called only on cache miss
    cache_id  = "my_result",                       # relative path under cache_base_directory
    ttl       = "1 day",                           # overrides instance default
)
```

### Forcing a refresh

```python
result = cache.execute_cached("mykey", callback, "my_result", rerun=True)
```

### Upstream-aware invalidation

```python
# Treat cache as stale if created before the data source was last updated
result = cache.execute_cached(
    "mykey", callback, "my_result",
    oldest_valid_cache_dt=last_db_update_time,   # timezone-aware datetime
)
```

### Low-level save / load

```python
# Save raw bytes
path = cache.save("subdir/myfile", data=plistlib.dumps(obj), key_name="mykey",
                  comment="human-readable label")

# Load raw bytes
data = cache.load("subdir/myfile")

# Load with metadata
data, meta = cache.load_entry("subdir/myfile")
# meta keys: "key", "created_at", "comment", "validasof_datetime"
```

### Check existence

```python
if cache.exists("subdir/myfile"):
    ...
```

### Deterministic filenames from descriptions

```python
fname = get_hashed_filename("accounts as of 2026-02")           # 32-char hex
fname = get_hashed_filename("accounts", length=16, prefix="mm") # "mm-<16hex>"
```

---

## Return shape convention

All `execute_cached` and `load` operations return the same Python object that was
passed to `save` (round-tripped through plistlib binary format). Supported types
are those serializable by `plistlib`: `dict`, `list`, `str`, `int`, `float`, `bool`,
`bytes`, `datetime`. The library validates serializability before writing; a
`ValueError` is raised if the callback returns an unsupported type.

`load_entry` returns `(bytes, dict)` — the raw decrypted bytes plus a metadata dict.
The caller is responsible for deserializing the bytes (typically `plistlib.loads`).

---

## Architecture

```
encrypted_cache/
  src/encrypted_cache/
    __init__.py   Public exports: EncryptedCache, SaltMismatchError, get_hashed_filename
    core.py       All implementation: EncryptedCache class, key derivation, TTL logic
  doc/
  scripts/
    pre-push-secret-scan.sh   Git hook: scan for accidental secret commits
```

---

## Error handling

| Situation | Exception | Notes |
|---|---|---|
| File written with different salt | `SaltMismatchError` (subclass of `ValueError`) | Caught inside `execute_cached`; treated as cache miss |
| Unknown key name | `ValueError("Unknown key: ...")` | Raised by `save`; not silently ignored |
| Callback returns non-plist data | `ValueError("callback must return plist-serializable data")` | |
| Absolute or traversal `cache_id` | `ValueError` | Path injection guard in `_resolve_cache_path` |
| Any read failure in `execute_cached` | logs warning, falls back to callback | Best-effort cache; never crashes on stale/corrupt files |

---

## Method signatures

All public method signatures are in `doc/AGENTS_api_signatures.txt` (relative to
library root).

---

## Source location

All paths below are relative to the library root.

| File | Role |
|---|---|
| `src/encrypted_cache/core.py` | Full implementation: `EncryptedCache`, `SaltMismatchError`, `get_hashed_filename` |
| `src/encrypted_cache/__init__.py` | Public re-exports |
