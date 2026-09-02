"""Frozen detection-owned defaults for strict fast prefilter behavior."""

from __future__ import annotations

STRICT_FAST_BENIGN_EXTENSIONS = frozenset((".txt", ".md", ".json", ".ini", ".cfg", ".log", ".csv"))
STRICT_FAST_BENIGN_MAX_BYTES = 65536
STRICT_FAST_BENIGN_BINARY_MAGIC = (b"MZ", b"\x7fELF", b"PK\x03\x04")
STRICT_FAST_BENIGN_DENY_TOKENS = ("powershell", "cmd.exe", "wget ", "curl ", "http://", "https://")
STRICT_FAST_BENIGN_BYPASS_VERSION = "strict_fast_benign_bypass_v2_after_prefilter"
DECODE_LAYER_MAX_DEPTH = 3

__all__ = (
    "DECODE_LAYER_MAX_DEPTH",
    "STRICT_FAST_BENIGN_BINARY_MAGIC",
    "STRICT_FAST_BENIGN_BYPASS_VERSION",
    "STRICT_FAST_BENIGN_DENY_TOKENS",
    "STRICT_FAST_BENIGN_EXTENSIONS",
    "STRICT_FAST_BENIGN_MAX_BYTES",
)
