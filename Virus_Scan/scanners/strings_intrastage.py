"""Scanner-owned intrastage string chunking and raw scan helpers."""

from Virus_Scan.contracts.result_record import scanner_degraded_tags
from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import intrastage_enabled, run_raw_task_queue, stage_parallel_workers
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scanners.config import load_scanner_limits_policy_snapshot
from Virus_Scan.scanners.payload_decode import decoded_payload_tags
from Virus_Scan.scanners.strings_collector_merge import merge_stage_collector_results
from Virus_Scan.scanners.text_contextual_tags import contextual_tag_scan
from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_text

_SCANNER_LIMITS_POLICY = load_scanner_limits_policy_snapshot()
INTRASTAGE_MIN_TEXT_CHARS = _SCANNER_LIMITS_POLICY.strings_intrastage_min_text_chars
INTRASTAGE_CHUNK_CHARS = _SCANNER_LIMITS_POLICY.strings_intrastage_chunk_chars
INTRASTAGE_CHUNK_OVERLAP = _SCANNER_LIMITS_POLICY.strings_intrastage_chunk_overlap
INTRASTAGE_MAX_CHUNKS = _SCANNER_LIMITS_POLICY.strings_intrastage_max_chunks


def _intrastage_text(value: object, *, default: object = '') -> object:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_intrastage_text",
        unsupported_reason="unsafe_intrastage_text_rejected",
    )
    return default if reason else text


def _intrastage_int(value: object, default: object, *, reason: object) -> object:
    number, _number_reason = no_hook_exact_nonnegative_int(
        value,
        default=default,
        reason=reason,
        non_finite_reason="non_finite_intrastage_integer",
    )
    return number


def _intrastage_prefix(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_intrastage_prefix",
        unsupported_reason="unsafe_intrastage_prefix_rejected",
    )
    return "intrastage" if reason or not text else text


def _intrastage_task_name(prefix: object, suffix: object) -> object:
    return prefix + suffix


def _split_text_for_intrastage(text: object, min_chars: object = None, chunk_chars: object = None, overlap: object = None, max_chunks: object = None) -> object:
    """Return balanced overlapped chunks for raw collector fan-out."""
    s = _intrastage_text(text)
    min_chars = _intrastage_int(min_chars, INTRASTAGE_MIN_TEXT_CHARS, reason="unsafe_intrastage_min_chars_rejected")
    base_chunk = max(8192, _intrastage_int(chunk_chars, INTRASTAGE_CHUNK_CHARS, reason="unsafe_intrastage_chunk_chars_rejected"))
    max_chunks = max(1, _intrastage_int(max_chunks, INTRASTAGE_MAX_CHUNKS, reason="unsafe_intrastage_max_chunks_rejected"))
    if not intrastage_enabled() or len(s) < min_chars:
        return [(0, s)] if s else []
    n = len(s)
    estimated = max(1, (n + base_chunk - 1) // base_chunk)
    if estimated > max_chunks:
        base_chunk = max(base_chunk, (n + max_chunks - 1) // max_chunks)
    overlap = max(0, min(_intrastage_int(overlap, INTRASTAGE_CHUNK_OVERLAP, reason="unsafe_intrastage_overlap_rejected"), base_chunk // 2))
    chunks = []
    start = 0
    while start < n:
        end = min(n, start + base_chunk)
        chunks.append((start, s[start:end]))
        if end >= n:
            break
        start = max(end - overlap, start + 1)
    return chunks


def _intrastage_contextual_chunk_raw(chunk: object, path: object = None, source: object = 'strings', offset: object = 0) -> object:
    """Scanner-owned raw contextual collector for one text chunk."""
    del offset  # Explicitly unused contract parameters.
    try:
        return list(contextual_tag_scan(chunk, path=path, source=source, finalize=False) or [])
    except SCAN_CONTENT_ERRORS as e:
        record_suppressed_failure('scanner_intrastage_context_failure', e, domain='scanner')
        return scanner_degraded_tags(['string_context_chunk_error'])


def _intrastage_decoded_chunk_raw(chunk: object, path: object = None, offset: object = 0) -> object:
    """Scanner-owned raw decoded-payload collector for one text chunk."""
    del offset  # Explicitly unused contract parameters.
    try:
        return list(decoded_payload_tags(chunk, path=path, finalize=False) or [])
    except SCAN_CONTENT_ERRORS as e:
        record_suppressed_failure('scanner_intrastage_decode_failure', e, domain='scanner')
        return scanner_degraded_tags(['string_decode_chunk_error'])


def _append_intrastage_string_tasks(tasks: object, strings_blob: object, path: object = None, source: object = 'strings', prefix: object = 'intrastage', *, include_context: object = True, include_decode: object = True) -> object:
    """Append chunk-level raw string/decode tasks to an existing task list."""
    prefix = _intrastage_prefix(prefix)
    chunks = _split_text_for_intrastage(strings_blob)
    if not chunks:
        return tasks
    if len(chunks) == 1:
        if include_context:
            tasks.append((_intrastage_task_name(prefix, '_context_raw'), _intrastage_contextual_chunk_raw, (chunks[0][1],), {'path': path, 'source': source, 'offset': chunks[0][0]}))
        if include_decode:
            tasks.append((_intrastage_task_name(prefix, '_decoded_raw'), _intrastage_decoded_chunk_raw, (chunks[0][1],), {'path': path, 'offset': chunks[0][0]}))
        return tasks
    for idx, (offset, chunk) in enumerate(chunks):
        idx_text = int.__str__(idx).zfill(2)
        if include_context:
            tasks.append((_intrastage_task_name(prefix, '_context_chunk_' + idx_text), _intrastage_contextual_chunk_raw, (chunk,), {'path': path, 'source': source, 'offset': offset}))
        if include_decode:
            tasks.append((_intrastage_task_name(prefix, '_decoded_chunk_' + idx_text), _intrastage_decoded_chunk_raw, (chunk,), {'path': path, 'offset': offset}))
    return tasks


def _raw_stage_scan_strings(strings_blob: object, path: object = None) -> object:
    """Raw-only string evidence collector for stage-parallel routes."""
    tags = []
    tags.extend(contextual_tag_scan(strings_blob, path=path, source='strings', finalize=False))
    tags.extend(decoded_payload_tags(strings_blob, path=path, finalize=False))
    return list(tags or [])


def _raw_stage_scan_strings_parallel(strings_blob: object, path: object = None, source: object = 'strings') -> object:
    """Parallel-friendly raw string/decode collector with scanner-owned merge."""
    local_tasks = []
    _append_intrastage_string_tasks(local_tasks, strings_blob, path=path, source=source, prefix='raw_strings', include_context=True, include_decode=True)
    if len(local_tasks) <= 2 or not intrastage_enabled():
        return _raw_stage_scan_strings(strings_blob, path=path)
    results = run_raw_task_queue(local_tasks, max_workers=stage_parallel_workers())
    tags, _meta, _suspicious, _errors = merge_stage_collector_results(results).as_tuple()
    return list(tags or [])


def intrastage_contextual_chunk_raw(chunk: object, path: object = None, source: object = 'strings', offset: object = 0) -> object:
    """Public strings-scanner contract for contextual raw chunk analysis."""
    return _intrastage_contextual_chunk_raw(chunk, path=path, source=source, offset=offset)


__all__ = (
    'INTRASTAGE_CHUNK_CHARS',
    'INTRASTAGE_CHUNK_OVERLAP',
    'INTRASTAGE_MAX_CHUNKS',
    'INTRASTAGE_MIN_TEXT_CHARS',
    '_append_intrastage_string_tasks',
    '_intrastage_contextual_chunk_raw',
    '_intrastage_decoded_chunk_raw',
    '_raw_stage_scan_strings',
    '_raw_stage_scan_strings_parallel',
    '_split_text_for_intrastage',
    'intrastage_contextual_chunk_raw',
)
