# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 @drakee
"""Tests for encrypted_cache (spec rfeat-010).

Covers the acceptance criteria from spec/rfeat-010-encrypted_cache.md.
"""
from __future__ import annotations

import json
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from encrypted_cache import (
    EncryptedCache,
    SaltMismatchError,
    get_hashed_filename,
)

SALT = b"test-salt-value"
SECRETS = {"default": "test-password-1", "other": "test-password-2"}


@pytest.fixture()
def cache_dir(tmp_path: Path) -> Path:
    """Return a temporary cache base directory."""
    d = tmp_path / "cache"
    d.mkdir()
    return d


@pytest.fixture()
def cache(cache_dir: Path) -> EncryptedCache:
    """Return an EncryptedCache wired to a temp directory."""
    return EncryptedCache(SECRETS, salt=SALT, cache_base_directory=cache_dir)


# ── AC: round-trip save / load ─────────────────────────────────────────────


class TestSaveLoadRoundTrip:
    """AC: EncryptedCache round-trips plist-serializable data through save/load."""

    def test_bytes_round_trip(self, cache: EncryptedCache, cache_dir: Path) -> None:
        payload = b'{"key": "value", "num": 42}'
        path = cache.save(cache_dir / "rt_test", payload, "default")
        assert cache.load(path) == payload

    def test_load_entry_returns_metadata(self, cache: EncryptedCache, cache_dir: Path) -> None:
        now = datetime.now(timezone.utc)
        payload = b"hello"
        path = cache.save(
            cache_dir / "meta_test", payload, "default",
            validasof_datetime=now, comment="test comment",
        )
        data, meta = cache.load_entry(path)
        assert data == payload
        assert meta["key"] == "default"
        assert meta["comment"] == "test comment"
        assert meta["validasof_datetime"] is not None
        assert meta["created_at"] is not None

    def test_different_keys_produce_different_ciphertext(
        self, cache: EncryptedCache, cache_dir: Path,
    ) -> None:
        payload = b"same data"
        p1 = cache.save(cache_dir / "k1", payload, "default")
        p2 = cache.save(cache_dir / "k2", payload, "other")
        raw1 = json.loads(p1.read_text())["encrypted"]
        raw2 = json.loads(p2.read_text())["encrypted"]
        assert raw1 != raw2

    def test_unknown_key_raises(self, cache: EncryptedCache, cache_dir: Path) -> None:
        with pytest.raises(ValueError, match="Unknown key"):
            cache.save(cache_dir / "bad", b"x", "nonexistent")

    def test_exists(self, cache: EncryptedCache, cache_dir: Path) -> None:
        assert not cache.exists(cache_dir / "nope")
        cache.save(cache_dir / "yes", b"data", "default")
        assert cache.exists(cache_dir / "yes")


# ── AC: execute_cached hit / miss ──────────────────────────────────────────


class TestExecuteCached:
    """AC: execute_cached returns cached data on hit, calls callback on miss."""

    def test_miss_then_hit(self, cache: EncryptedCache) -> None:
        cb = MagicMock(return_value={"val": 1})
        r1 = cache.execute_cached("default", cb, "ec_test", ttl="1 day")
        r2 = cache.execute_cached("default", cb, "ec_test", ttl="1 day")
        assert r1 == {"val": 1}
        assert r2 == {"val": 1}
        assert cb.call_count == 1  # second call is a cache hit

    def test_non_plist_callback_raises(self, cache: EncryptedCache) -> None:
        with pytest.raises(ValueError, match="plist-serializable"):
            cache.execute_cached("default", lambda: object(), "bad_plist")


# ── AC: salt mismatch ──────────────────────────────────────────────────────


class TestSaltMismatch:
    """AC: Changing the salt invalidates existing cache files."""

    def test_load_entry_raises_on_salt_mismatch(
        self, cache: EncryptedCache, cache_dir: Path,
    ) -> None:
        path = cache.save(cache_dir / "salt_test", b"data", "default")
        cache2 = EncryptedCache(SECRETS, salt=b"different-salt", cache_base_directory=cache_dir)
        with pytest.raises(SaltMismatchError):
            cache2.load_entry(path)

    def test_execute_cached_re_executes_on_salt_mismatch(
        self, cache: EncryptedCache, cache_dir: Path,
    ) -> None:
        cb = MagicMock(return_value="first")
        cache.execute_cached("default", cb, "sm_test")

        cache2 = EncryptedCache(SECRETS, salt=b"other-salt", cache_base_directory=cache_dir)
        cb2 = MagicMock(return_value="second")
        result = cache2.execute_cached("default", cb2, "sm_test")
        assert result == "second"
        cb2.assert_called_once()


# ── AC: TTL expiry ─────────────────────────────────────────────────────────


class TestTTLExpiry:
    """AC: TTL expiry causes a cache miss and callback re-execution."""

    def test_expired_duration_triggers_recompute(
        self, cache: EncryptedCache, cache_dir: Path,
    ) -> None:
        cb = MagicMock(return_value="v1")
        cache.execute_cached("default", cb, "ttl_test", ttl="1 second")

        # Patch created_at to the past so the entry is expired
        envelope_path = cache._resolve_cache_path("ttl_test", None)
        envelope = json.loads(envelope_path.read_text())
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        envelope["created_at"] = past
        envelope_path.write_text(json.dumps(envelope))

        cb2 = MagicMock(return_value="v2")
        result = cache.execute_cached("default", cb2, "ttl_test", ttl="1 second")
        assert result == "v2"
        cb2.assert_called_once()

    def test_ttl_zero_always_stale(self, cache: EncryptedCache) -> None:
        cb = MagicMock(return_value="a")
        cache.execute_cached("default", cb, "ttl0_test", ttl="1 day")
        cb2 = MagicMock(return_value="b")
        result = cache.execute_cached("default", cb2, "ttl0_test", ttl=0)
        assert result == "b"
        cb2.assert_called_once()

    def test_ttl_infinite_never_expires(self, cache: EncryptedCache) -> None:
        cb = MagicMock(return_value="inf")
        cache.execute_cached("default", cb, "inf_test", ttl="infinite")

        # Backdate created_at far into the past
        envelope_path = cache._resolve_cache_path("inf_test", None)
        envelope = json.loads(envelope_path.read_text())
        envelope["created_at"] = "2000-01-01T00:00:00+00:00"
        envelope_path.write_text(json.dumps(envelope))

        cb2 = MagicMock(return_value="should not run")
        result = cache.execute_cached("default", cb2, "inf_test", ttl="infinite")
        assert result == "inf"
        cb2.assert_not_called()

    def test_ttl_none_uses_instance_default(self, cache_dir: Path) -> None:
        """ttl=None in execute_cached falls back to the instance default_ttl."""
        short_cache = EncryptedCache(SECRETS, salt=SALT, cache_base_directory=cache_dir, ttl="1 second")
        cb = MagicMock(return_value="val")
        short_cache.execute_cached("default", cb, "default_ttl_test", ttl=None)

        # Backdate so the 1-second default expires
        envelope_path = short_cache._resolve_cache_path("default_ttl_test", None)
        envelope = json.loads(envelope_path.read_text())
        envelope["created_at"] = "2000-01-01T00:00:00+00:00"
        envelope_path.write_text(json.dumps(envelope))

        cb2 = MagicMock(return_value="recomputed")
        result = short_cache.execute_cached("default", cb2, "default_ttl_test", ttl=None)
        assert result == "recomputed"
        cb2.assert_called_once()

    def test_ttl_absolute_datetime(self, cache: EncryptedCache) -> None:
        cb = MagicMock(return_value="dt")
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        cache.execute_cached("default", cb, "dt_test", ttl="1 day")
        cb2 = MagicMock(return_value="nope")
        result = cache.execute_cached("default", cb2, "dt_test", ttl=future)
        assert result == "dt"
        cb2.assert_not_called()

    def test_ttl_duration_string_formats(self, cache: EncryptedCache) -> None:
        """Various human-readable duration strings are accepted."""
        cb = MagicMock(return_value="ok")
        for ttl_str in ("5 days", "3d 2h", "30m", "10s", "1 hour 30 minutes"):
            cache.execute_cached("default", cb, f"dur_{ttl_str}", ttl=ttl_str)

    def test_ttl_infinite_string(self, cache: EncryptedCache) -> None:
        cb = MagicMock(return_value="forever")
        for label in ("infinite", "inf", "forever"):
            cache.execute_cached("default", cb, f"inf_{label}", ttl=label)
        assert cb.call_count == 3  # each is a new cache_id, so callback runs


# ── AC: oldest_valid_cache_dt ─────────────────────────────────────────────────────────


class TestNotBefore:
    """AC: oldest_valid_cache_dt invalidates cache entries created before the given timestamp."""

    def test_cache_older_than_oldest_valid_cache_dt_triggers_recompute(
        self, cache: EncryptedCache,
    ) -> None:
        cb = MagicMock(return_value="old")
        cache.execute_cached("default", cb, "nb_test", ttl="1 day")

        # oldest_valid_cache_dt in the future → cache is stale
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        cb2 = MagicMock(return_value="fresh")
        result = cache.execute_cached("default", cb2, "nb_test", ttl="1 day", oldest_valid_cache_dt=future)
        assert result == "fresh"
        cb2.assert_called_once()

    def test_cache_newer_than_oldest_valid_cache_dt_is_hit(
        self, cache: EncryptedCache,
    ) -> None:
        cb = MagicMock(return_value="cached")
        cache.execute_cached("default", cb, "nb_hit_test", ttl="1 day")

        # oldest_valid_cache_dt in the past → cache is still valid
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        cb2 = MagicMock(return_value="should not run")
        result = cache.execute_cached("default", cb2, "nb_hit_test", ttl="1 day", oldest_valid_cache_dt=past)
        assert result == "cached"
        cb2.assert_not_called()

    def test_oldest_valid_cache_dt_without_tzinfo_assumes_utc(
        self, cache: EncryptedCache,
    ) -> None:
        cb = MagicMock(return_value="val")
        cache.execute_cached("default", cb, "nb_naive_test", ttl="1 day")

        # naive datetime in the future → should still invalidate
        future_naive = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)
        cb2 = MagicMock(return_value="recomputed")
        result = cache.execute_cached("default", cb2, "nb_naive_test", ttl="1 day", oldest_valid_cache_dt=future_naive)
        assert result == "recomputed"
        cb2.assert_called_once()

    def test_oldest_valid_cache_dt_none_has_no_effect(self, cache: EncryptedCache) -> None:
        cb = MagicMock(return_value="val")
        cache.execute_cached("default", cb, "nb_none_test", ttl="1 day")

        cb2 = MagicMock(return_value="nope")
        result = cache.execute_cached("default", cb2, "nb_none_test", ttl="1 day", oldest_valid_cache_dt=None)
        assert result == "val"
        cb2.assert_not_called()


# ── AC: rerun=True ─────────────────────────────────────────────────────────


class TestRerun:
    """AC: rerun=True bypasses the cache unconditionally."""

    def test_rerun_ignores_cache(self, cache: EncryptedCache) -> None:
        cb1 = MagicMock(return_value="old")
        cache.execute_cached("default", cb1, "rerun_test")
        cb2 = MagicMock(return_value="new")
        result = cache.execute_cached("default", cb2, "rerun_test", rerun=True)
        assert result == "new"
        cb2.assert_called_once()


# ── AC: path traversal ─────────────────────────────────────────────────────


class TestPathTraversal:
    """AC: Path traversal attempts raise ValueError."""

    @pytest.mark.parametrize("bad_id", [
        "/etc/passwd",
        "../outside",
        "sub/../../escape",
        "",
        ".",
    ])
    def test_bad_cache_ids_rejected(self, cache: EncryptedCache, bad_id: str) -> None:
        with pytest.raises(ValueError):
            cache.execute_cached("default", lambda: "x", bad_id)


# ── AC: file permissions ──────────────────────────────────────────────────


class TestFilePermissions:
    """AC: Cache directories 0o700, files 0o600."""

    def test_directory_permissions(self, cache: EncryptedCache, cache_dir: Path) -> None:
        subdir = cache_dir / "perm_sub"
        cache.save(subdir / "test", b"data", "default")
        dir_mode = stat.S_IMODE(subdir.stat().st_mode)
        assert dir_mode == 0o700

    def test_file_permissions(self, cache: EncryptedCache, cache_dir: Path) -> None:
        path = cache.save(cache_dir / "perm_file", b"data", "default")
        file_mode = stat.S_IMODE(path.stat().st_mode)
        assert file_mode == 0o600


# ── AC: get_hashed_filename ────────────────────────────────────────────────


class TestGetHashedFilename:
    """AC: get_hashed_filename produces stable hex output and validates input."""

    def test_deterministic(self) -> None:
        a = get_hashed_filename("hello world")
        b = get_hashed_filename("hello world")
        assert a == b

    def test_default_length(self) -> None:
        result = get_hashed_filename("test")
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)

    def test_custom_length(self) -> None:
        assert len(get_hashed_filename("test", length=8)) == 8
        assert len(get_hashed_filename("test", length=64)) == 64

    def test_with_prefix(self) -> None:
        result = get_hashed_filename("test", prefix="api-call")
        assert result.startswith("api-call-")

    def test_prefix_sanitisation(self) -> None:
        result = get_hashed_filename("test", prefix="My Call!!")
        assert result.startswith("my-call-")

    def test_length_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="length must be"):
            get_hashed_filename("x", length=7)
        with pytest.raises(ValueError, match="length must be"):
            get_hashed_filename("x", length=65)

    def test_empty_prefix_raises(self) -> None:
        with pytest.raises(ValueError, match="alphanumeric"):
            get_hashed_filename("x", prefix="!!!")

    def test_different_inputs_differ(self) -> None:
        assert get_hashed_filename("a") != get_hashed_filename("b")


# ── Edge cases: corrupted envelope, custom suffix ─────────────────────────


class TestCorruptedEnvelope:
    """Corrupted cache files should fall back to recomputation."""

    def test_garbage_envelope_falls_back(self, cache: EncryptedCache) -> None:
        cb = MagicMock(return_value="original")
        cache.execute_cached("default", cb, "corrupt_test")

        envelope_path = cache._resolve_cache_path("corrupt_test", None)
        envelope_path.write_text("NOT VALID JSON {{{")

        cb2 = MagicMock(return_value="fresh")
        result = cache.execute_cached("default", cb2, "corrupt_test")
        assert result == "fresh"
        cb2.assert_called_once()

    def test_truncated_envelope_falls_back(self, cache: EncryptedCache) -> None:
        cb = MagicMock(return_value="original")
        cache.execute_cached("default", cb, "trunc_test")

        envelope_path = cache._resolve_cache_path("trunc_test", None)
        envelope = json.loads(envelope_path.read_text())
        envelope.pop("encrypted")
        envelope_path.write_text(json.dumps(envelope))

        cb2 = MagicMock(return_value="fresh")
        result = cache.execute_cached("default", cb2, "trunc_test")
        assert result == "fresh"
        cb2.assert_called_once()


class TestCustomSuffix:
    """Custom suffix round-trips correctly."""

    def test_custom_suffix_round_trip(self, cache_dir: Path) -> None:
        c = EncryptedCache(SECRETS, salt=SALT, cache_base_directory=cache_dir, suffix=".cache")
        path = c.save(cache_dir / "custom", b"payload", "default")
        assert path.name.endswith(".cache")
        assert c.load(path) == b"payload"

    def test_custom_suffix_execute_cached(self, cache_dir: Path) -> None:
        c = EncryptedCache(SECRETS, salt=SALT, cache_base_directory=cache_dir, suffix=".cache")
        cb = MagicMock(return_value={"ok": True})
        result = c.execute_cached("default", cb, "suffix_test")
        assert result == {"ok": True}
        envelope_path = c._resolve_cache_path("suffix_test", None)
        assert envelope_path.name.endswith(".cache")


class TestStrSalt:
    """Salt can be passed as str and is UTF-8 encoded to bytes internally."""

    def test_str_salt_round_trip(self, cache_dir: Path) -> None:
        c = EncryptedCache(SECRETS, salt="text-salt", cache_base_directory=cache_dir)
        path = c.save(cache_dir / "str_salt", b"payload", "default")
        assert c.load(path) == b"payload"

    def test_str_salt_equivalent_to_bytes(self, cache_dir: Path) -> None:
        c_str = EncryptedCache(SECRETS, salt="same-salt", cache_base_directory=cache_dir)
        c_bytes = EncryptedCache(SECRETS, salt=b"same-salt", cache_base_directory=cache_dir)
        path = c_str.save(cache_dir / "equiv_test", b"data", "default")
        assert c_bytes.load(path) == b"data"
