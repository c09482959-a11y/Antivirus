"""Base64 candidate policy and strict decode helpers for the payload decoder."""
from __future__ import annotations

import base64
import re

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.scanners.contracts import PayloadDecodeResult, scanner_contract_text
from Virus_Scan.scanners.contracts.payload_result import PayloadFailureRequest
from Virus_Scan.scanners.payload.policy import DECODE_LAYER_MAX_TEXT_BYTES, DECODE_LAYER_MIN_B64_CHARS

def _b64_alphabet_kind(candidate: str) -> str:
    c = scanner_contract_text(candidate).strip()
    body = c.rstrip("=")
    if not body:
        return "invalid"
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", c):
        return "standard"
    if re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", c):
        return "urlsafe"
    return "invalid"

def _likely_base64_candidate(candidate: str) -> tuple[bool, str]:
    result = (False, "prefilter_error")
    try:
        c = re.sub(r"\s+", "", scanner_contract_text(candidate))
        body = c.rstrip("=")
        kind = _b64_alphabet_kind(c)
        if len(c) < DECODE_LAYER_MIN_B64_CHARS:
            result = (False, "too_short")
        elif len(c) > DECODE_LAYER_MAX_TEXT_BYTES * 2:
            result = (False, "too_large")
        elif len(body) % 4 == 1:
            result = (False, "bad_length_mod4")
        elif c.count("=") > 2 or ("=" in c and not c.endswith("=" * c.count("="))):
            result = (False, "bad_padding")
        elif kind == "invalid":
            result = (False, "bad_alphabet")
        elif re.fullmatch(r"[0-9a-fA-F]+", body):
            result = (False, "looks_like_hex")
        else:
            classes = sum(bool(re.search(rx, body)) for rx in (r"[A-Z]", r"[a-z]", r"[0-9]", r"[+/_-]"))
            result = (True, kind) if classes >= 2 else (False, "low_diversity")
    except SCAN_CONTENT_ERRORS:
        result = (False, "prefilter_error")
    return result

def _strict_b64_decode_result(candidate: str, *, depth: int = 0, b64decode: object = base64.b64decode, urlsafe_b64decode: object = base64.urlsafe_b64decode) -> PayloadDecodeResult:
    ok, kind = _likely_base64_candidate(candidate)
    if not ok:
        return PayloadDecodeResult.failure(
            PayloadFailureRequest(
                encoding="base64",
                stage="base64_prefilter",
                error=kind,
                depth=depth,
                state="unsupported",
                error_category="payload_decode_prefilter_rejected",
            )
        )
    c = re.sub(r"\s+", "", scanner_contract_text(candidate))
    padded = c + "=" * ((4 - len(c) % 4) % 4)
    try:
        if kind == "urlsafe":
            return PayloadDecodeResult.success("base64", urlsafe_b64decode(padded))
        return PayloadDecodeResult.success("base64", b64decode(padded, validate=True))
    except SCAN_CONTENT_ERRORS as exc:
        return PayloadDecodeResult.failure(
            PayloadFailureRequest(
                encoding="base64",
                stage="base64_decode",
                error=exc,
                depth=depth,
                state="malformed",
                error_category="malformed_payload_decode",
            )
        )

def _strict_b64_decode(candidate: str, *, b64decode: object = base64.b64decode, urlsafe_b64decode: object = base64.urlsafe_b64decode) -> bytes | None:
    result = _strict_b64_decode_result(candidate, b64decode=b64decode, urlsafe_b64decode=urlsafe_b64decode)
    if result.ok:
        return result.decoded
    return None

__all__ = ("_b64_alphabet_kind", "_likely_base64_candidate", "_strict_b64_decode", "_strict_b64_decode_result")
