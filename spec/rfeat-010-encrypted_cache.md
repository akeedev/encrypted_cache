# rfeat-010 — encrypted_cache

> Reverse-engineered feature spec for `encrypted_cache`.

## Purpose

Encrypt plist-serializable data at rest and serve it through a TTL-aware
cache-or-compute pattern.  Typical use case: caching API responses or
expensive computations on disk so they survive process restarts, while
keeping the payload unreadable without the correct password + salt.

## Module: `encrypted_cache`

### `get_hashed_filename(text, length=32, prefix=None) -> str`

Standalone utility.  Produces a deterministic, filesystem-safe hex string
from arbitrary input via SHA-256 truncation.  Used to derive cache IDs
from human-readable callback descriptions.

- `length` must be 8..64.
- `prefix` is sanitised (lowered, non-alnum replaced with `-`) and
  prepended as `<prefix>-<hash>`.

### `SaltMismatchError(ValueError)`

Raised when an on-disk envelope was written with a different salt
fingerprint than the one the current `EncryptedCache` instance holds.

### `EncryptedCache`

**Construction** — accepts a `secrets` dict mapping logical names to
passwords, a shared `salt`, an optional `suffix`, `cache_base_directory`,
and a default `ttl`.  A Fernet cipher is derived for each secret via
PBKDF2-HMAC-SHA256 (480 000 iterations).

**Public methods:**

| Method | Description |
|---|---|
| `save(filepath, data, key_name, ...)` | Encrypt raw bytes and write a JSON envelope to disk. |
| `load(filepath)` | Decrypt and return raw bytes. |
| `load_entry(filepath)` | Decrypt and return `(bytes, metadata_dict)`. |
| `exists(filepath)` | Check whether the envelope file exists. |
| `execute_cached(key_name, callback, cache_id, ...)` | Cache-or-compute: return cached data if valid, else run callback, encrypt result, store, and return. |

**Envelope format** (cleartext JSON):

```json
{
  "key": "<key_name>",
  "salt_sha256": "<16-char hex fingerprint>",
  "created_at": "<ISO-8601 UTC>",
  "comment": "<optional>",
  "encrypted": "<Fernet token>"
}
```

The Fernet token decrypts to a binary plist: `{"data": <bytes>, "validasof_datetime": "..."}`.

**TTL resolution** in `execute_cached`:

1. Explicit `ttl` parameter wins; else instance `default_ttl` (default `"5 days"`).
2. Accepted forms: `None` (infinite), `0` (always stale), duration string
   (`"3d 5h"`), ISO-8601 absolute datetime.
3. On `SaltMismatchError` the entry is silently treated as a cache miss.

**Upstream-aware invalidation** via `oldest_valid_cache_dt`:

An optional `datetime` parameter.  When set, cache entries whose
`created_at` is older than this timestamp are treated as stale —
independent of TTL.  A cache entry must pass both TTL *and*
`oldest_valid_cache_dt` checks to be considered valid.  Naive datetimes
are assumed UTC.

**Filesystem hardening:**

- Directories: `0o700`, files: `0o600`.
- Path traversal prevention: rejects absolute, empty, or `..`-containing
  cache IDs and verifies the resolved path stays below the base directory.

## Acceptance criteria

- [ ] `EncryptedCache` round-trips arbitrary plist-serializable data through
      `save` / `load` without loss.
- [ ] Corrupted or unreadable cache entries are treated as cache misses and
      trigger callback execution.
- [ ] `execute_cached` returns cached data on hit, calls callback on miss,
      and stores the result.
- [ ] Changing the salt invalidates existing cache files
      (`SaltMismatchError` or silent re-execution).
- [ ] TTL expiry causes a cache miss and callback re-execution.
- [ ] `rerun=True` bypasses the cache unconditionally.
- [ ] Path traversal attempts (`..`, absolute paths) raise `ValueError`.
- [ ] Cache directories are created with `0o700`, files with `0o600`.
- [ ] `get_hashed_filename` produces stable hex output and rejects
      out-of-range lengths.
- [ ] `oldest_valid_cache_dt` invalidates cache entries created before
      the given timestamp, even when TTL has not expired.
- [ ] `oldest_valid_cache_dt=None` has no effect on cache validity.

## Threat model

### Protected against

| Threat | Mitigation |
|---|---|
| **Casual disk read** — another user or process reads cache files. | Fernet encryption (AES-128-CBC + HMAC-SHA256); restrictive file permissions (`0o600`/`0o700`). |
| **Tampering / bit-flip** — attacker modifies the ciphertext. | Fernet's HMAC verification rejects altered tokens. |
| **Stale-salt replay** — old cache files re-introduced after a salt rotation. | Salt fingerprint comparison; mismatch triggers re-computation. |
| **Path traversal** — malicious `cache_id` escapes the base directory. | Validation rejects `..`, absolute paths, and paths resolving outside the base. |
| **Brute-force key derivation** — offline dictionary attack on weak passwords. | PBKDF2 with 480 000 iterations raises cost substantially. |

### NOT protected against

| Threat | Reason |
|---|---|
| **Root / same-UID access** — attacker runs as the same user or as root. | File permissions and encryption keys live in the same process memory; no hardware-backed key storage. |
| **Memory inspection** — attacker reads process memory or swap. | Fernet keys and plaintext exist in Python heap; no secure-memory primitives. |
| **Password strength** — weak passwords chosen by the caller. | The module derives keys but does not enforce password policies. |
| **Metadata leakage** — key name, timestamp, comment, salt fingerprint are cleartext. | By design: envelope metadata is intentionally readable for diagnostics. |
| **Denial of service** — attacker deletes or corrupts cache files. | No integrity store outside the files themselves; corruption causes re-computation, not detection of an attack. |
| **Multi-process race conditions** — concurrent writers to the same cache file. | No file locking; last writer wins. |
