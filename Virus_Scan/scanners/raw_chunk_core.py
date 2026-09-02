"""Raw chunk scanner core policy, anchors, and shared helpers."""
from __future__ import annotations

from pathlib import Path
import re
from typing import Callable, Iterable

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_sequence_items, no_hook_text, no_hook_type_name
from Virus_Scan.scanners.config.loader import load_raw_chunk_policy_snapshot, load_scanner_limits_policy_snapshot

PLR2004N0_55 = 0.55
PLR2004N126 = 126
PLR2004N32 = 32

_RAW_CHUNK_POLICY = load_raw_chunk_policy_snapshot()
_SCANNER_LIMITS_POLICY = load_scanner_limits_policy_snapshot()
DEFAULT_GLOBAL_RAW_CONTEXT_ANCHORS = _RAW_CHUNK_POLICY.context_anchors
DEFAULT_GLOBAL_RAW_DECODE_ANCHORS = _RAW_CHUNK_POLICY.decode_anchors


def _raw_text_status(value: object, *, missing_reason: object = "missing_raw_chunk_text", unsupported_reason: object = "unsafe_raw_chunk_text_rejected") -> object:
    return no_hook_text(value, missing_reason=missing_reason, unsupported_reason=unsupported_reason)


def _raw_text(value: object, *, default: object = "") -> object:
    text, reason = _raw_text_status(value)
    return default if reason else text


def _raw_nonnegative_int(value: object, default: object, *, reason: object = "unsafe_raw_chunk_integer_rejected") -> object:
    number, number_reason = no_hook_exact_nonnegative_int(
        value,
        default=default,
        reason=reason,
        non_finite_reason="non_finite_raw_chunk_integer",
    )
    return number, number_reason


def _raw_anchor_status(anchors: object, *, field: object) -> object:
    if anchors is None:
        return ("valid", ())
    if type(anchors) is str:
        return ("valid", (str.__str__(anchors),))
    if type(anchors) in (tuple, list, set, frozenset):
        return ("valid", tuple(anchors))
    return ("anchor_probe_error", TypeError(field + "_rejected"))


def _raw_anchor_text(anchor: object) -> object:
    return no_hook_text(
        anchor,
        missing_reason="missing_raw_anchor_text",
        unsupported_reason="unsafe_raw_anchor_text_rejected",
    )


def _raw_tags(value: object) -> object:
    return list(no_hook_sequence_items(value))


def _raw_report_extra_path(path: object) -> object:
    text, reason = no_hook_text(
        path,
        missing_reason="missing_raw_chunk_path",
        unsupported_reason="unsafe_raw_chunk_path_rejected",
    )
    return "" if reason else text


def _raw_offset(value: object) -> object:
    offset, _reason = _raw_nonnegative_int(value, 0, reason="unsafe_raw_chunk_offset_rejected")
    return offset


def raw_printable_ratio(text: object, sample_limit: object = 8192) -> object:
    sample_text, text_reason = _raw_text_status(text)
    limit, limit_reason = _raw_nonnegative_int(sample_limit, 8192, reason="unsafe_raw_chunk_sample_limit_rejected")
    if text_reason or limit_reason:
        return -1.0
    sample = sample_text[:limit]
    if not sample:
        return 0.0
    printable = sum(1 for char in sample if char in '\r\n\t' or PLR2004N32 <= ord(char) <= PLR2004N126)
    return printable / max(1, len(sample))

def context_anchor_status(context_anchors: Iterable[str] = DEFAULT_GLOBAL_RAW_CONTEXT_ANCHORS) -> object:
    """Return explicit raw-context anchor status without fail-open exception returns."""
    return _raw_anchor_status(context_anchors, field="raw_context_anchor")

def decode_anchor_status(decode_anchors: Iterable[str] = DEFAULT_GLOBAL_RAW_DECODE_ANCHORS) -> object:
    """Return explicit raw-decode anchor status without fail-open exception returns."""
    return _raw_anchor_status(decode_anchors, field="raw_decode_anchor")

def should_context_scan(text: object, *, context_anchors: Iterable[str] | None = None, report: Callable[[str, BaseException], object] | None = None) -> object:
    sample, sample_reason = _raw_text_status(text, unsupported_reason="unsafe_raw_context_text_rejected")
    if sample_reason:
        if report is not None:
            report("raw_context_text_boundary_failed", ValueError(sample_reason))
        return True
    if not sample:
        return False
    lowered = sample.lower()
    anchor_source = DEFAULT_GLOBAL_RAW_CONTEXT_ANCHORS if context_anchors is None else context_anchors
    anchor_state, anchors = context_anchor_status(anchor_source)
    if anchor_state != 'valid':
        if report is not None:
            failure = anchors if isinstance(anchors, BaseException) else TypeError("raw_context_anchor_rejected")
            report('raw_context_anchor_boundary_failed', failure)
        return True
    if not isinstance(anchors, tuple):
        return True
    for anchor in anchors:
        anchor_text, anchor_reason = _raw_anchor_text(anchor)
        if anchor_reason:
            if report is not None:
                report('raw_context_anchor_text_failed', ValueError(anchor_reason))
            return True
        if anchor_text.lower() in lowered:
            return True
    return False

def should_decode_scan(text: object, *, decode_anchors: Iterable[str] | None = None, report: Callable[[str, BaseException], object] | None = None) -> object:
    sample, sample_reason = _raw_text_status(text, unsupported_reason="unsafe_raw_decode_text_rejected")
    if sample_reason:
        if report is not None:
            report("raw_decode_text_boundary_failed", ValueError(sample_reason))
        return False
    if not sample:
        return False
    lowered = sample.lower()
    anchor_source = DEFAULT_GLOBAL_RAW_DECODE_ANCHORS if decode_anchors is None else decode_anchors
    anchor_state, anchors = decode_anchor_status(anchor_source)
    if anchor_state != 'valid':
        if report is not None:
            failure = anchors if isinstance(anchors, BaseException) else TypeError("raw_decode_anchor_rejected")
            report('raw_decode_anchor_boundary_failed', failure)
        return True
    if not isinstance(anchors, tuple):
        return True
    for anchor in anchors:
        anchor_text, anchor_reason = _raw_anchor_text(anchor)
        if anchor_reason:
            if report is not None:
                report('raw_decode_anchor_text_failed', ValueError(anchor_reason))
            return True
        if anchor_text.lower() in lowered:
            return True
    if raw_printable_ratio(sample) < PLR2004N0_55:
        return False
    return re.search(r'[A-Za-z0-9+/]{80,}={0,2}', sample) is not None

def decoded_chunk_tags(
    chunk: object,
    *,
    path: object = None,
    offset: object = 0,
    decoded_payload_tags: Callable[..., object],
    scanner_degraded_tags: Callable[..., object],
    report: Callable[..., object],
    decode_anchors: Iterable[str] = DEFAULT_GLOBAL_RAW_DECODE_ANCHORS,
) -> object:
    if not should_decode_scan(chunk, decode_anchors=decode_anchors, report=report):
        return []
    try:
        return _raw_tags(decoded_payload_tags(chunk, path=path, finalize=False))
    except TypeError:
        try:
            return _raw_tags(decoded_payload_tags(chunk, path=path))
        except (OSError, RuntimeError, TypeError, ValueError, UnicodeError) as exc:
            report('intrastage_decoded_chunk_failed', exc, fatal=False, extra={'path': _raw_report_extra_path(path), 'offset': _raw_offset(offset)})
            return _raw_tags(scanner_degraded_tags(['raw_decoded_chunk_failed']))
    except (OSError, RuntimeError, ValueError, UnicodeError) as exc:
        report('intrastage_decoded_chunk_failed', exc, fatal=False, extra={'path': _raw_report_extra_path(path), 'offset': _raw_offset(offset)})
        return _raw_tags(scanner_degraded_tags(['raw_decoded_chunk_failed']))

def read_range_text(
    path: object,
    *,
    start: object = 0,
    size: object = None,
    default_size: object = None,
    range_error_cls: type[BaseException] = RuntimeError,
) -> str:
    """Read a deterministic latin-1 raw text range for chunk collectors."""
    fallback_size = _SCANNER_LIMITS_POLICY.raw_chunk_default_read_size if default_size is None else default_size
    offset, offset_reason = _raw_nonnegative_int(start, 0, reason="unsafe_raw_range_start_rejected")
    amount, amount_reason = _raw_nonnegative_int(size, fallback_size, reason="unsafe_raw_range_size_rejected")
    if offset_reason or amount_reason:
        reason = offset_reason or amount_reason
        raise range_error_cls("raw range read failed: " + reason)
    try:
        with Path(path).open("rb") as handle:
            handle.seek(offset)
            data = handle.read(max(0, amount))
        return data.decode("latin1", errors="ignore")
    except (OSError, ValueError, TypeError) as exc:
        raise range_error_cls("raw range read failed: " + no_hook_type_name(exc)) from exc

def _contextual_chunk_tags(text: object, *, path: object, source: object, collector: object, start: object, should_context_scan_func: object, contextual_scan: object, context_failure: object) -> object:
    sample, sample_reason = _raw_text_status(text, unsupported_reason="unsafe_raw_contextual_chunk_text_rejected")
    if sample_reason:
        return context_failure([], collector, ValueError(sample_reason), path=path, start=start)
    if not should_context_scan_func(sample.lower()):
        return []
    try:
        return _raw_tags(contextual_scan(text, path=path, source=source, finalize=False))
    except TypeError:
        try:
            return _raw_tags(contextual_scan(text, path=path, source=source))
        except (OSError, RuntimeError, TypeError, ValueError, UnicodeError) as exc:
            return context_failure([], collector, exc, path=path, start=start)
    except (OSError, RuntimeError, ValueError, UnicodeError) as exc:
        return context_failure([], collector, exc, path=path, start=start) 

__all__ = (
    "DEFAULT_GLOBAL_RAW_CONTEXT_ANCHORS",
    "DEFAULT_GLOBAL_RAW_DECODE_ANCHORS",
    "_SCANNER_LIMITS_POLICY",
    "context_anchor_status",
    "decode_anchor_status",
    "decoded_chunk_tags",
    "raw_printable_ratio",
    "read_range_text",
    "should_context_scan",
    "should_decode_scan",
)
