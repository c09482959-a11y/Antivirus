"""Base64 and protocol probes for pickle fast escalation."""
from __future__ import annotations

import re

from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.payload.base64_policy import _strict_b64_decode_result
from Virus_Scan.scanners.pickle.protocol import has_pickle_protocol_header

PLR2004N8192 = 8192

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError
)
_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_FAST_ESCALATION_MAX_BYTES = _PICKLE_POLICY.fast_escalation_max_bytes
PICKLE_FAST_B64_SAMPLE_MAX = _PICKLE_POLICY.fast_b64_sample_max


def _pickle_fast_b64_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='missing_pickle_fast_base64_text',
        unsupported_reason='unsafe_pickle_fast_base64_text_rejected',
    )
    return '' if reason else text


def _strict_b64_decode(candidate: object) -> object:
    result = _strict_b64_decode_result(candidate)
    if result.ok:
        return result.decoded
    return None


def _pickle_fast_protocol_hint(data: object) -> object:
    """True if a small byte sample looks like it contains a pickle stream.

    Conversion/probe failures are intentionally allowed to propagate to the
    owning caller so they become explicit scanner failure evidence instead of a
    fail-open protocol hit.
    """
    return has_pickle_protocol_header(data, max_bytes=PICKLE_FAST_ESCALATION_MAX_BYTES)


def _pickle_fast_base64_status(text: object) -> object:
    """Cheaply detect base64 pickle fragments and malformed decode candidates."""
    malformed = 0
    try:
        sample = _pickle_fast_b64_text(text)[:PICKLE_FAST_B64_SAMPLE_MAX]
        for match in re.finditer('[A-Za-z0-9+/_=-]{24,}', sample):
            candidate = match.group(0)
            if len(candidate) > PLR2004N8192:
                candidate = candidate[:8192]
            try:
                raw = _strict_b64_decode(candidate)
            except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS:
                malformed += 1
                continue
            if not raw:
                malformed += 1
                continue
            if raw and raw[:2] in (b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05'):
                return True, malformed
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        try:
            record_suppressed_failure('suppressed_exception', exc, domain='runtime')
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as reporting_exc:
            _ = reporting_exc
        malformed += 1
    return False, malformed


def _pickle_fast_base64_protocol_hint(text: object) -> object:
    """Cheaply detect base64 fragments that decode to a pickle protocol header."""
    try:
        found, _malformed = _pickle_fast_base64_status(text)
        return bool(found)
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        try:
            record_suppressed_failure('suppressed_exception', exc, domain='runtime')
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as reporting_exc:
            _ = reporting_exc
    return False


__all__ = ('_pickle_fast_base64_protocol_hint', '_pickle_fast_base64_status', '_pickle_fast_protocol_hint')
