# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 @drakee
"""encrypted_cache — password-based encryption with TTL-aware cache-or-compute pattern.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
USE AT YOUR OWN RISK.

Version : 0.2
Date    : 2026-02-15
Author  : @drakee
Repository: https://github.com/akeedev/encrypted-cache
"""
from encrypted_cache.core import (
    EncryptedCache,
    SaltMismatchError,
    get_hashed_filename,
)

__all__ = [
    "EncryptedCache",
    "SaltMismatchError",
    "get_hashed_filename",
]
