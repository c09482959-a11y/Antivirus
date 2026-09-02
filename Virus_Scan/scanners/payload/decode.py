"""Canonical scanner-owned payload decode chain traversal."""
from __future__ import annotations

import binascii
import re
import urllib.parse

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.scanners.contracts import scanner_contract_nonnegative_int, scanner_contract_text
from Virus_Scan.scanners.payload.base64_policy import _likely_base64_candidate, _strict_b64_decode_result
from Virus_Scan.scanners.payload.chain import _try_decoder_chain
from Virus_Scan.scanners.payload.evidence import _payload_decode_failure_record
from Virus_Scan.scanners.payload.policy import (
    _PAYLOAD_POLICY,
    DECODE_LAYER_MAX_CANDIDATES,
    DECODE_LAYER_MIN_B64_CHARS,
    DECODE_LAYER_MIN_HEX_CHARS,
)
from Virus_Scan.scanners.payload.records import _record_decoded_result

def safe_decode_payloads(strings_blob: str, max_depth: int | None = None, *, b64decode: object = None, urlsafe_b64decode: object = None) -> list[dict[str, object]]:
    """Safely decode bounded base64/hex/url/zlib/gzip payload candidates."""
    results: list[dict[str, object]] = []
    seen: set[str] = set()
    depth_limit = scanner_contract_nonnegative_int(_PAYLOAD_POLICY.default_max_depth if max_depth is None else max_depth, replacement=_PAYLOAD_POLICY.default_max_depth)
    queue: list[tuple[str, int, str, list[str]]] = [(scanner_contract_text(strings_blob), 0, "root", [])]
    while queue and len(results) < DECODE_LAYER_MAX_CANDIDATES:
        blob, depth, parent, chain = queue.pop(0)
        if not blob or depth >= depth_limit:
            continue
        candidates: list[tuple[str, str]] = []
        for m in re.finditer(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{%d,}={0,2})(?![A-Za-z0-9+/=_-])" % DECODE_LAYER_MIN_B64_CHARS, blob):
            cand = m.group(1)
            ok, _reason = _likely_base64_candidate(cand)
            if ok:
                candidates.append(("base64", cand))
            if len(candidates) >= DECODE_LAYER_MAX_CANDIDATES:
                break
        for m in re.finditer(r"(?:\\x[0-9A-Fa-f]{2}){%d,}" % (DECODE_LAYER_MIN_HEX_CHARS // 4), blob):
            candidates.append(("hex_escape", m.group(0)))
            if len(candidates) >= DECODE_LAYER_MAX_CANDIDATES:
                break
        for m in re.finditer(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{%d,})(?![0-9A-Fa-f])" % DECODE_LAYER_MIN_HEX_CHARS, blob):
            cand = m.group(1)
            if len(cand) % 2 == 0:
                candidates.append(("hex", cand))
            if len(candidates) >= DECODE_LAYER_MAX_CANDIDATES:
                break
        for m in re.finditer(r"(?:%[0-9A-Fa-f]{2}){8,}", blob):
            candidates.append(("url_percent", m.group(0)))
            if len(candidates) >= DECODE_LAYER_MAX_CANDIDATES:
                break
        for encoding, cand in candidates:
            if len(results) >= DECODE_LAYER_MAX_CANDIDATES:
                break
            try:
                raw = b""
                if encoding == "base64":
                    decode_kwargs = {}
                    if b64decode is not None:
                        decode_kwargs["b64decode"] = b64decode
                    if urlsafe_b64decode is not None:
                        decode_kwargs["urlsafe_b64decode"] = urlsafe_b64decode
                    decoded_result = _strict_b64_decode_result(cand, depth=depth + 1, **decode_kwargs)
                    if not decoded_result.ok:
                        if decoded_result.failure_evidence:
                            results.append(decoded_result.to_failure_record(depth=depth + 1))
                        continue
                    raw = decoded_result.decoded
                elif encoding == "hex_escape":
                    raw = bytes.fromhex("".join(token[2:] for token in re.findall(r"\\x[0-9A-Fa-f]{2}", cand)))
                elif encoding == "hex":
                    raw = binascii.unhexlify(cand)
                elif encoding == "url_percent":
                    raw = urllib.parse.unquote_to_bytes(cand)
                next_chain = [*list(chain or []), encoding]
                records_to_queue: list[dict[str, object]] = []
                rec = _record_decoded_result(results, seen, raw, encoding, cand, depth + 1, parent, next_chain)
                if rec:
                    records_to_queue.append(rec)
                for expanded, expanded_name in _try_decoder_chain(raw, encoding):
                    expanded_chain = [*list(chain or []), expanded_name]
                    rec2 = _record_decoded_result(results, seen, expanded, expanded_name, cand, depth + 1, parent, expanded_chain)
                    if rec2:
                        records_to_queue.append(rec2)
                if depth + 1 < depth_limit:
                    queue.extend(
                        (
                            rec_item.get("text", ""),
                            depth + 1,
                            rec_item.get("sha256", encoding),
                            rec_item.get("decode_chain", next_chain),
                        )
                        for rec_item in records_to_queue
                    )
            except SCAN_CONTENT_ERRORS as exc:
                results.append(_payload_decode_failure_record("safe_decode_payloads", exc, encoding=encoding, depth=depth + 1))
                continue
    return results

__all__ = ("safe_decode_payloads",)
