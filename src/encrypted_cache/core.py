# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 @drakee
"""encrypted_cache - encrypt and cache plist-serializable data on disk.

Provides password-based encryption (Fernet / PBKDF2-HMAC-SHA256) with
cleartext metadata envelopes for TTL-based cache invalidation.

Classes
-------
EncryptedCache
    Main facade: derives per-name Fernet keys from passwords + a shared salt,
    then encrypts/decrypts payloads stored as JSON envelope files on disk.
    ``execute_cached()`` implements the cache-or-compute pattern with TTL
    expiry and optional ``oldest_valid_cache_dt`` for upstream-aware
    invalidation.

SaltMismatchError
    Raised when a cached file was written with a different salt than the
    one currently configured.

Functions
---------
get_hashed_filename
    Produce a deterministic, filesystem-safe hex filename from an arbitrary
    string via SHA-256.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
USE AT YOUR OWN RISK.

Version : 0.2
Date    : 2026-02-15
Author  : @drakee
Repository: https://github.com/akeedev/encrypted-cache
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import json
import plistlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Union

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger("encrypted_cache")

# Type alias for values that must survive a plist round-trip
PlistData = Any


def _get_path_relative_to_home(p: Path) -> Path:
    """Return a path relative to the user's home directory, if possible."""
    resolved = p.resolve()
    try:
        home = Path.home()
        tilde_path = Path("~") / resolved.relative_to(home)
    except ValueError:
        tilde_path = resolved
    return tilde_path


def get_hashed_filename(text: str, length: int = 32, prefix: str | None = None) -> str:
    """Return a truncated SHA-256 hex digest suitable as a cache filename.

    Parameters
    ----------
    text : str
        Arbitrary input string (e.g. a callback description) to hash.
    length : int
        Number of hex characters to keep (8..64).
    prefix : str | None
        If given, prepended as ``<prefix>-<hash>``.  Non-alphanumeric
        characters are replaced with hyphens.

    Returns
    -------
    str
        A filesystem-safe identifier derived from *text*.

    Raises
    ------
    ValueError
        If *length* is out of range or *prefix* contains no alphanumeric chars.
    """
    if length < 8 or length > 64:
        raise ValueError("length must be between 8 and 64")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    trimmed = digest[:length]
    if prefix is None:
        return trimmed
    safe_prefix = re.sub(r"[^a-z0-9_-]+", "-", prefix.lower()).strip("-")
    if not safe_prefix:
        raise ValueError("prefix must contain at least one alphanumeric character")
    return f"{safe_prefix}-{trimmed}"


class SaltMismatchError(ValueError):
    """Raised when the salt used to encrypt does not match the current salt."""


class EncryptedCache:
    """Encrypt and cache plist-serializable payloads on disk.

    Each payload is stored as a JSON envelope containing cleartext metadata
    (key name, creation timestamp, salt fingerprint, optional comment) and a
    Fernet-encrypted inner payload (the actual data plus an optional
    ``validasof_datetime``).

    Parameters
    ----------
    secrets : dict[str, str]
        Mapping of logical key names to passwords.  A Fernet cipher is
        derived for each entry via PBKDF2-HMAC-SHA256.
    salt : bytes
        Shared salt for key derivation.  Changing the salt invalidates all
        previously written cache files.
    suffix : str
        File extension for cache envelopes (default ``".enc.json"``).
    cache_base_directory : str | Path | None
        Root directory for cache files.  When *None*, defaults to
        ``<project_root>/data/encryptedcache`` or a per-user ``/tmp`` fallback.
    ttl : datetime | str | None
        Default time-to-live applied by ``execute_cached`` when the caller
        does not pass an explicit TTL.  Accepts a duration string
        (``"5 days"``), an absolute datetime, or *None* for infinity.
    """

    DEFAULT_CACHE_BASE_DIRECTORY = Path("data") / "encryptedcache"
    DEFAULT_TTL = "5 days"

    def _project_root(self) -> Path | None:
        """Find project root by walking up to a ``pyproject.toml``."""
        current = Path.cwd().resolve()
        for parent in [current, *current.parents]:
            if (parent / "pyproject.toml").is_file():
                return parent
        return None

    def _default_cache_base_directory(self) -> Path:
        """Pick a cache directory based on project-root availability."""
        project_root = self._project_root()
        if project_root is not None:
            return project_root / self.DEFAULT_CACHE_BASE_DIRECTORY
        else:
            fallback = Path(f"/tmp/encryptedcache-{os.getuid()}")
            logger.warning("No pyproject.toml found, using fallback cache dir: %s", fallback)
            return fallback

    @staticmethod
    def _salt_fingerprint(salt: bytes) -> str:
        """Return a short hex fingerprint of the salt for envelope storage."""
        return hashlib.sha256(salt).hexdigest()[:16]

    def __init__(
        self,
        secrets: dict[str, str],
        salt: str|bytes,             # note: if salt is str, it will be UTF-8-encode to bytes
        suffix: str = ".enc.json",
        cache_base_directory: Union[str, Path] | None = None,
        ttl: datetime | str | None = None,
    ):
        if isinstance(salt, str):
            salt = salt.encode("utf-8")
        self._salt = salt
        self._salt_fp = self._salt_fingerprint(salt)
        self.ciphers: dict[str, Fernet] = {}
        self._suffix = suffix
        base_dir = Path(cache_base_directory) if cache_base_directory else self._default_cache_base_directory()
        self.cache_base_directory = base_dir
        self.default_ttl = ttl if ttl is not None else self.DEFAULT_TTL
        for name, password in secrets.items():
            logger.debug("Deriving key for %r", name)
            key = self._derive_key(password, salt)
            self.ciphers[name] = Fernet(key)
        logger.info(
            "Initialized EncryptedCache with %d key(s), base_dir=%s, default_ttl=%s",
            len(self.ciphers), self.cache_base_directory, self.default_ttl,
        )

    def __str__(self) -> str:
        """Return a string representation of the EncryptedCache instance."""
        p = _get_path_relative_to_home(self.cache_base_directory)
        return f"EncryptedCache(salt={self._salt!r}, cache_base_dir='{p}', ttl={self.default_ttl})"

    # -- filesystem helpers --------------------------------------------------

    def _ensure_secure_dir(self, path: Path) -> None:
        """Create *path* (and parents) with mode 0o700 (user-only access)."""
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o700)

    def _write_secure_json(self, filepath: Path, payload: dict[str, Any]) -> None:
        """Write *payload* as JSON with mode 0o600."""
        self._ensure_secure_dir(filepath.parent)
        fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)

    # -- cryptography --------------------------------------------------------

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a Fernet key from *password* and *salt* via PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,  # OWASP 2023 minimum recommendation for PBKDF2-HMAC-SHA256
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # -- path handling -------------------------------------------------------

    def _normalize_path(self, filepath: Union[str, Path]) -> Path:
        """Ensure *filepath* ends with the configured suffix."""
        path = Path(filepath)
        name = path.name
        if name.endswith(self._suffix):
            return path
        for suffix in (self._suffix, ".enc.json", ".enc.xml", ".enc"):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
                result = path.with_name(name + self._suffix)
                logger.debug("Normalized path: %s -> %s", filepath, result)
                return result
        result = path.with_name(name + self._suffix)
        logger.debug("Normalized path: %s -> %s", filepath, result)
        return result

    def _resolve_cache_path(self, cache_id: str, cache_base_directory: Union[str, Path] | None) -> Path:
        """Resolve a relative *cache_id* against the base directory.

        Raises ValueError on absolute paths, empty IDs, or path traversal.
        """
        base_dir = Path(cache_base_directory) if cache_base_directory else self.cache_base_directory
        cache_path = Path(cache_id)
        if cache_path.is_absolute():
            raise ValueError("cache_id must be relative")
        if not cache_path.parts or cache_path.parts == (".",):
            raise ValueError("cache_id must not be empty")
        if ".." in cache_path.parts:
            raise ValueError("cache_id must not contain path traversal")
        # stricter check: resolved path must stay below base_dir
        candidate = (base_dir / cache_path).resolve(strict=False)
        base_resolved = base_dir.resolve(strict=False)
        if not candidate.is_relative_to(base_resolved):
            raise ValueError("cache_id must stay within cache_base_directory")
        resolved = self._normalize_path(candidate)
        logger.debug("Resolved cache path: %s", resolved)
        return resolved

    # -- datetime / TTL helpers ----------------------------------------------

    def _format_datetime(self, value: datetime, label: str) -> str:
        """Format a timezone-aware datetime as ISO-8601."""
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError(f"{label} must be timezone-aware")
        return value.isoformat()

    def _parse_datetime(self, value: str, label: str) -> datetime:
        """Parse an ISO-8601 string; assume UTC when no timezone is present."""
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError(f"{label} must be ISO-8601, got {value!r}") from exc
        if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed

    def _parse_duration(self, value: str) -> timedelta | None:
        """Parse a human-readable duration string into a timedelta.

        Examples: ``"3d 5h 30m"``, ``"5 days"``, ``"infinite"``.
        Returns *None* for infinite durations.
        """
        normalized = value.strip().lower()
        if normalized in {"infinite", "inf", "forever"}:
            return None
        tokens = re.findall(r"(\d+)\s*(days?|d|hours?|h|minutes?|mins?|m|seconds?|secs?|s)", normalized)
        if not tokens:
            raise ValueError(f"Invalid duration string: {value!r}")

        total = timedelta()
        for amount_str, unit in tokens:
            amount = int(amount_str)
            if unit in {"d", "day", "days"}:
                total += timedelta(days=amount)
            elif unit in {"h", "hour", "hours"}:
                total += timedelta(hours=amount)
            elif unit in {"m", "min", "mins", "minute", "minutes"}:
                total += timedelta(minutes=amount)
            elif unit in {"s", "sec", "secs", "second", "seconds"}:
                total += timedelta(seconds=amount)
        logger.debug("Parsed duration %r -> %s", value, total)
        return total

    def _is_cache_valid(self, created_at: str | None, ttl: datetime | str | int | None) -> bool:
        """Return whether a cache entry is still fresh.

        *ttl* semantics: *None* = infinite, ``0`` = always stale, a
        ``datetime`` = absolute expiry, a ``str`` = either an ISO-8601
        timestamp or a duration like ``"5 days"``.
        """
        if ttl is None:
            valid = True
        elif isinstance(ttl, int) and ttl == 0:
            valid = False
        elif isinstance(ttl, datetime):
            now = datetime.now(timezone.utc)
            expires_at = ttl
            if expires_at.tzinfo is None or expires_at.utcoffset() is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            valid = now <= expires_at
        elif isinstance(ttl, str):
            now = datetime.now(timezone.utc)
            try:
                expires_at = self._parse_datetime(ttl, "ttl")
                valid = now <= expires_at
            except ValueError:
                duration = self._parse_duration(ttl)
                if duration is None:
                    valid = True
                elif created_at is None:
                    valid = False
                else:
                    created_dt = self._parse_datetime(created_at, "created_at")
                    valid = now <= created_dt + duration
        else:
            raise TypeError("ttl must be datetime, str, int(0), or None")
        logger.debug("Cache validity check: created_at=%s, ttl=%s, valid=%s", created_at, ttl, valid)
        return valid

    def _check_salt_fingerprint(self, payload: dict[str, Any], filepath: Path) -> None:
        """Raise ``SaltMismatchError`` if the envelope salt differs from ours."""
        stored_fp = payload.get("salt_sha256")
        logger.debug("Salt fingerprint check: stored=%s, current=%s", stored_fp, self._salt_fp)
        if stored_fp is not None and stored_fp != self._salt_fp:
            raise SaltMismatchError(
                f"Salt mismatch for {filepath.name}: "
                f"file has {stored_fp}, current is {self._salt_fp}"
            )

    # -- public API ----------------------------------------------------------

    def save(
        self,
        filepath: Union[str, Path],
        data: bytes,
        key_name: str = "default",
        validasof_datetime: datetime | None = None,
        comment: str | None = None,
    ) -> Path:
        """Encrypt *data* and write it with metadata to disk.

        Parameters
        ----------
        filepath : str | Path
            Target file path (suffix is normalised automatically).
        data : bytes
            Raw payload to encrypt.
        key_name : str
            Logical key name (must exist in the ``secrets`` passed to the
            constructor).
        validasof_datetime : datetime | None
            Optional "valid-as-of" timestamp stored inside the encrypted
            envelope.
        comment : str | None
            Optional cleartext comment stored in the outer envelope.

        Returns
        -------
        Path
            The normalised path the envelope was written to.
        """
        if key_name not in self.ciphers:
            raise ValueError(f"Unknown key: {key_name}")

        filepath = self._normalize_path(filepath)
        inner_payload: dict[str, Any] = {
            "data": data,
        }
        if validasof_datetime is not None:
            inner_payload["validasof_datetime"] = self._format_datetime(validasof_datetime, "validasof_datetime")

        encrypted = self.ciphers[key_name].encrypt(
            plistlib.dumps(inner_payload, fmt=plistlib.FMT_BINARY, sort_keys=True)
        )

        payload: dict[str, str] = {
            "key": key_name,
            "salt_sha256": self._salt_fp,
            "created_at": self._format_datetime(datetime.now(timezone.utc), "created_at"),
            "encrypted": encrypted.decode("utf-8"),
        }
        if comment is not None:
            payload["comment"] = comment

        self._write_secure_json(filepath, payload)
        logger.debug("Saved encrypted cache: %s (key=%s)", filepath, key_name)
        return filepath

    def load(self, filepath: Union[str, Path]) -> bytes:
        """Load and decrypt data from a cache file.

        Parameters
        ----------
        filepath : str | Path
            Path to the envelope file.

        Returns
        -------
        bytes
            The decrypted payload.
        """
        data, _meta = self.load_entry(filepath)
        return data

    def load_entry(self, filepath: Union[str, Path]) -> tuple[bytes, dict[str, str | None]]:
        """Load data plus metadata from a cache file.

        Parameters
        ----------
        filepath : str | Path
            Path to the envelope file.

        Returns
        -------
        tuple[bytes, dict]
            ``(decrypted_data, metadata)`` where *metadata* contains
            ``key``, ``created_at``, ``comment``, and ``validasof_datetime``.

        Raises
        ------
        SaltMismatchError
            If the file was written with a different salt.
        """
        filepath = self._normalize_path(filepath)
        payload = json.loads(filepath.read_text())
        key_name = payload["key"]

        self._check_salt_fingerprint(payload, filepath)

        if key_name not in self.ciphers:
            raise ValueError(f"Key '{key_name}' not available")

        encrypted = payload["encrypted"].encode("utf-8")
        inner_payload = plistlib.loads(self.ciphers[key_name].decrypt(encrypted))
        data = inner_payload["data"]
        validasof_datetime = inner_payload.get("validasof_datetime")

        metadata: dict[str, str | None] = {
            "key": key_name,
            "created_at": payload.get("created_at"),
            "comment": payload.get("comment"),
            "validasof_datetime": validasof_datetime,
        }
        logger.debug("Loaded cache entry: %s (key=%s)", filepath, key_name)
        return data, metadata

    def exists(self, filepath: Union[str, Path]) -> bool:
        """Return whether the cache envelope file exists on disk."""
        filepath = self._normalize_path(filepath)
        return filepath.exists()

    def execute_cached(
        self,
        key_name: str,
        callback: Callable[[], PlistData],
        cache_id: str,
        rerun: bool = False,
        ttl: datetime | str | int | None = None,
        oldest_valid_cache_dt: datetime | None = None,
        cache_base_directory: Union[str, Path] | None = None,
        validasof_datetime: datetime | None = None,
        comment: str | None = None,
    ) -> PlistData:
        """Load from cache or run *callback* and store the result.

        Implements the cache-or-compute pattern: if a valid cache file
        exists for *cache_id*, its decrypted contents are returned.
        Otherwise *callback* is invoked, the result is encrypted and
        stored, and then returned.

        Parameters
        ----------
        key_name : str
            Logical key name used for encryption.
        callback : Callable[[], PlistData]
            Zero-argument callable that produces the data to cache.
        cache_id : str
            Relative path (under *cache_base_directory*) used as cache key.
        rerun : bool
            Force re-execution even when a valid cache entry exists.
        ttl : datetime | str | int | None
            Time-to-live override.  Falls back to the instance default.
        oldest_valid_cache_dt : datetime | None
            If given, cache entries created before this timestamp are
            treated as stale.  Useful when the upstream data source is
            known to have been updated at a specific time.
        cache_base_directory : str | Path | None
            Override for the instance-level base directory.
        validasof_datetime : datetime | None
            Stored inside the encrypted envelope.
        comment : str | None
            Cleartext comment in the outer envelope.

        Returns
        -------
        PlistData
            The (possibly cached) result of *callback*.

        Raises
        ------
        ValueError
            If *callback* returns data that is not plist-serializable.
        """
        cache_path = self._resolve_cache_path(cache_id, cache_base_directory)
        effective_ttl = ttl if ttl is not None else self.default_ttl

        if rerun:
            logger.warning("Forced rerun for %s, ignoring cached data", cache_path)
        elif cache_path.exists():
            try:
                data, metadata = self.load_entry(cache_path)
            except SaltMismatchError:
                logger.warning("Salt mismatch for %s, treating as cache miss", cache_path)
            except Exception as exc:  # best-effort cache: fall back to callback on any read failure
                logger.warning("Failed to load cache %s (%s), treating as cache miss", cache_path, exc)
            else:
                if self._is_cache_valid(metadata.get("created_at"), effective_ttl):
                    created_at_str = metadata.get("created_at")
                    if oldest_valid_cache_dt is None:
                        logger.debug("Not checking for stale cache entries (oldest_valid_cache_dt is None).")
                    if oldest_valid_cache_dt is not None and created_at_str is not None:
                        created_dt = self._parse_datetime(created_at_str, "created_at")
                        nb = oldest_valid_cache_dt if oldest_valid_cache_dt.tzinfo is not None else oldest_valid_cache_dt.replace(tzinfo=timezone.utc)
                        if created_dt < nb:
                            logger.debug("Cache predates oldest_valid_cache_dt (%s) for %s, re-executing", oldest_valid_cache_dt, cache_path)
                        else:
                            logger.debug("Cache hit for %s", cache_path)
                            return plistlib.loads(data)
                    else:
                        logger.debug("Cache hit for %s", cache_path)
                        return plistlib.loads(data)
                else:
                    logger.debug("Cache expired for %s, re-executing callback", cache_path)

        if not rerun:
            logger.debug("Cache miss for %s, executing callback", cache_path)

        result = callback()
        self._validate_plist_data(result)
        payload = plistlib.dumps(result, fmt=plistlib.FMT_BINARY, sort_keys=True)
        self.save(cache_path, payload, key_name, validasof_datetime=validasof_datetime, comment=comment)
        return result

    def _validate_plist_data(self, value: PlistData) -> None:
        """Ensure *value* survives a plist round-trip."""
        try:
            plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("callback must return plist-serializable data") from exc
