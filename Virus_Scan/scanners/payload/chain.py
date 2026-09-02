"""Bounded compressed payload expansion chain."""
from __future__ import annotations

import bz2
import gzip
import lzma
import zlib

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.scanners.contracts import scanner_contract_bytes, scanner_contract_error_message, scanner_contract_join, scanner_contract_text
from Virus_Scan.scanners.payload.policy import DECODE_LAYER_MAX_TEXT_BYTES

PLR2004N8 = 8


def _try_decoder_chain(raw: bytes, encoding_hint: str = "raw") -> list[tuple[bytes, str]]:
    out: list[tuple[bytes, str]] = []
    try:
        data = scanner_contract_bytes(raw)
        encoding_text = scanner_contract_text(encoding_hint, replacement="raw") or "raw"
        if not data or len(data) > DECODE_LAYER_MAX_TEXT_BYTES:
            return []
        decoders = (
            ("zlib", zlib.decompress),
            ("gzip", gzip.decompress),
            ("bz2", bz2.decompress),
            ("lzma", lzma.decompress),
            ("raw_deflate", lambda b: zlib.decompress(b, -15)),
        )
        for name, fn in decoders:
            try:
                decoded = fn(data)
                if decoded and PLR2004N8 <= len(decoded) <= DECODE_LAYER_MAX_TEXT_BYTES:
                    out.append((decoded, scanner_contract_join(encoding_text, "+", name)))
            except (OSError, EOFError, ValueError, zlib.error, gzip.BadGzipFile, lzma.LZMAError):
                continue
    except SCAN_CONTENT_ERRORS as exc:
        return [(scanner_contract_error_message(exc).encode("utf-8", "replace")[:512], "decoder_chain_failure")]
    return out

def expand_payload_decoder_chain(raw: bytes, encoding_hint: str = "raw") -> list[tuple[bytes, str]]:
    """Return bounded decompressed byte views from the canonical payload decoder."""
    return _try_decoder_chain(raw, encoding_hint=encoding_hint)

__all__ = ("_try_decoder_chain", "expand_payload_decoder_chain")
