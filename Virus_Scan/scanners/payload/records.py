"""Canonical decoded-payload record construction and embedded payload window discovery."""
from __future__ import annotations

import hashlib
import re

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.scanners.contracts import scanner_contract_bytes, scanner_contract_join, scanner_contract_text
from Virus_Scan.scanners.payload.chain import _try_decoder_chain
from Virus_Scan.scanners.payload.evidence import _payload_decode_failure_record
from Virus_Scan.scanners.payload.policy import DECODE_LAYER_MAX_TEXT_BYTES

PLR2004N126 = 126
PLR2004N32 = 32


def _decode_printable_ratio(raw: bytes) -> float:
    data = bytes(raw or b"")[:4096]
    if not data:
        return 0.0
    printable = sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126)
    return printable / max(1, len(data))

def _decoded_payload_interesting(text: str, raw: bytes = b"") -> bool:
    low = scanner_contract_text(text).lower()
    if raw and (raw.startswith((b"MZ", b"\x7fELF", b"PK\x03\x04"))):
        return True
    anchors = (
        "powershell", "cmd.exe", "subprocess", "os.system", "eval(", "exec(",
        "child_process", "http://", "https://", "websocket", "downloadstring",
        "frombase64string", "createprocess", "virtualalloc", "writeprocessmemory",
        "token", "password", "cookie", "wallet", "discord.com/api/webhooks",
    )
    return any(anchor in low for anchor in anchors)

def _record_decoded_result(results: list[dict[str, object]], seen: set[str], raw: bytes, encoding: str, cand: str, depth: int, parent: str, chain: list[str] | None = None) -> dict[str, object] | None:
    try:
        raw = scanner_contract_bytes(raw)
        if not raw or len(raw) > DECODE_LAYER_MAX_TEXT_BYTES or len(raw) < 8:
            return None
        views: list[str] = []
        for enc in ("utf-8", "utf-16le", "latin1"):
            try:
                txt = raw.decode(enc, errors="ignore")
                if txt and txt not in views:
                    views.append(txt)
            except UnicodeError:
                continue
        if not views:
            return None
        text_view = max(views, key=lambda t: sum(1 for ch in t[:4096] if ch in {"\n", "\t"} or PLR2004N32 <= ord(ch) <= PLR2004N126))
        if _decode_printable_ratio(raw) < 0.35 and not (raw.startswith((b"MZ", b"\x7fELF", b"PK\x03\x04"))):
            return None
        if not _decoded_payload_interesting(text_view, raw):
            return None
        key = hashlib.sha256(raw).hexdigest()
        if key in seen:
            return None
        seen.add(key)
        rec = {
            "encoding": encoding,
            "depth": depth,
            "parent": parent,
            "parent_sha256": parent if re.fullmatch(r"[0-9a-f]{64}", scanner_contract_text(parent)) else "",
            "raw_sample": scanner_contract_text(cand)[:96],
            "text": text_view[:DECODE_LAYER_MAX_TEXT_BYTES],
            "byte_len": len(raw),
            "sha256": key,
            "evidence_id": scanner_contract_join("decoded:", key[:16]),
            "decode_chain": list(chain or [encoding]),
            "binary_magic": "pe" if raw.startswith(b"MZ") else "elf" if raw.startswith(b"\x7fELF") else "zip" if raw.startswith(b"PK\x03\x04") else "",
        }
        results.append(rec)
        return rec
    except SCAN_CONTENT_ERRORS as exc:
        rec = _payload_decode_failure_record("record_decoded_result", exc, encoding=encoding, depth=depth)
        results.append(rec)
        return rec

def _decoded_payload_record_from_raw(raw: bytes, encoding: str, *, depth: int = 0, parent: str = "", raw_sample: str = "", chain: list[str] | None = None) -> dict[str, object] | None:
    """Return one canonical decoded-payload record for already-decoded bytes."""
    records: list[dict[str, object]] = []
    seen: set[str] = set()
    return _record_decoded_result(records, seen, raw, encoding, raw_sample or encoding, depth, parent, chain or [encoding])

def decoded_payload_records_from_bytes(raw: bytes | bytearray | str | None, *, encoding_hint: str = "raw", include_raw: bool = True, depth: int = 0, parent: str = "") -> list[dict[str, object]]:
    """Return canonical decoded payload records from byte data.

    This is the scanner-owned byte-level decoder authority used by pickle,
    archive/RPA, Ren'Py, binary, and detection consumers.  Domain scanners may
    decide which byte windows to pass in, but decompression and decoded-payload
    record shaping stay here so failures and evidence have one format.
    """
    records: list[dict[str, object]] = []
    seen: set[str] = set()
    try:
        if raw is None:
            return []
        if isinstance(raw, str):
            data = scanner_contract_text(raw).encode("latin1", errors="ignore")
        elif type(raw) in (bytes, bytearray):
            data = bytes(raw)
        else:
            data = b""
        data = data[:DECODE_LAYER_MAX_TEXT_BYTES]
        if not data:
            return []
        if include_raw:
            _record_decoded_result(records, seen, data, encoding_hint, encoding_hint, depth, parent, [encoding_hint])
        for expanded, expanded_name in _try_decoder_chain(data, encoding_hint):
            _record_decoded_result(records, seen, expanded, expanded_name, encoding_hint, depth + 1, parent, [encoding_hint, expanded_name])
    except SCAN_CONTENT_ERRORS as exc:
        records.append(_payload_decode_failure_record("decoded_payload_records_from_bytes", exc, encoding=encoding_hint, depth=depth))
    return records

def embedded_payload_records_from_bytes(raw: bytes | bytearray | str | None, *, encoding_hint: str = "raw", max_offsets: int = 32) -> list[dict[str, object]]:
    """Find embedded compressed payload windows using the canonical payload decoder."""
    records: list[dict[str, object]] = []
    seen_offsets: set[tuple[bytes, int]] = set()
    try:
        if raw is None:
            return []
        if isinstance(raw, str):
            blob = scanner_contract_text(raw).encode("latin1", errors="ignore")
        elif type(raw) in (bytes, bytearray):
            blob = bytes(raw)
        else:
            blob = b""
        blob = blob[:DECODE_LAYER_MAX_TEXT_BYTES]
        if not blob:
            return []
        starts: list[tuple[bytes, int]] = []
        for sig in (b"x\x01", b"x^", b"x\x9c", b"x\xda", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00"):
            start = 0
            while True:
                idx = blob.find(sig, start)
                if idx < 0:
                    break
                starts.append((sig, idx))
                if len(starts) >= max_offsets:
                    break
                start = idx + 1
            if len(starts) >= max_offsets:
                break
        for sig, off in starts[:max_offsets]:
            if (sig, off) in seen_offsets:
                continue
            seen_offsets.add((sig, off))
            chunk = blob[off:min(len(blob), off + DECODE_LAYER_MAX_TEXT_BYTES)]
            off_text = int.__str__(off)
            for rec in decoded_payload_records_from_bytes(chunk, encoding_hint=scanner_contract_join(scanner_contract_text(encoding_hint, replacement="raw"), "@", off_text), include_raw=False, depth=0, parent=off_text):
                if rec.get("failure_tags"):
                    rec.setdefault("container_offset", off)
                    records.append(rec)
                    continue
                if rec.get("text") or rec.get("binary_magic"):
                    rec.setdefault("container_offset", off)
                    records.append(rec)
    except SCAN_CONTENT_ERRORS as exc:
        records.append(_payload_decode_failure_record("embedded_payload_records_from_bytes", exc, encoding=encoding_hint, depth=0))
    return records

__all__ = (
    "_decode_printable_ratio",
    "_decoded_payload_interesting",
    "_decoded_payload_record_from_raw",
    "_record_decoded_result",
    "decoded_payload_records_from_bytes",
    "embedded_payload_records_from_bytes",
)
