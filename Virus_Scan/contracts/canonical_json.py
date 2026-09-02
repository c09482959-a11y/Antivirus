"""Canonical JSON serialization and SHA-256 identity primitives.

This contract module is the single owner for deterministic JSON bytes used by
cross-layer immutable identities.  Callers must supply already bounded,
JSON-safe primitive payloads.
"""
from __future__ import annotations

from hashlib import sha256
import json


def canonical_json_dumps(payload: object) -> str:
    """Serialize a bounded primitive payload deterministically."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def canonical_json_sha256(payload: object) -> str:
    """Return the SHA-256 of the canonical UTF-8 JSON representation."""
    return sha256(canonical_json_dumps(payload).encode("utf-8")).hexdigest()


__all__ = ("canonical_json_dumps", "canonical_json_sha256")
