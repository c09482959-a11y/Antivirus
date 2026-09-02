"""Canonical scanner-owned string scanning public surface."""

from dataclasses import dataclass

from Virus_Scan.contracts.result_record import scanner_degraded_tags
from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import intrastage_enabled, run_raw_task_queue, stage_parallel_workers
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scanners.payload_decode import decoded_payload_tags
from Virus_Scan.scanners.strings_ast import _umige_ast_enriched_strings
from Virus_Scan.scanners.strings_collector_merge import merge_stage_collector_results
from Virus_Scan.scanners.strings_finalization import normalize_string_tags
from Virus_Scan.scanners.strings_intrastage import (
    INTRASTAGE_CHUNK_CHARS,
    INTRASTAGE_CHUNK_OVERLAP,
    INTRASTAGE_MAX_CHUNKS,
    INTRASTAGE_MIN_TEXT_CHARS,
    _append_intrastage_string_tasks,
    _intrastage_contextual_chunk_raw,
    _intrastage_decoded_chunk_raw,
    _raw_stage_scan_strings,
    _raw_stage_scan_strings_parallel,
    _split_text_for_intrastage,
    intrastage_contextual_chunk_raw,
)
from Virus_Scan.scanners.text_api_mapping import primary_behavior_for_tag
from Virus_Scan.scanners.text_contextual_tags import contextual_tag_scan


def _strings_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='missing_scanner_strings_text',
        unsupported_reason='unsafe_scanner_strings_text_rejected',
    )
    return '' if reason else text


@dataclass(frozen=True, slots=True)
class ScanStringsRequest:
    strings_blob: object
    path: object = None
    finalize: object = True
    contextual_scanner: object = contextual_tag_scan
    payload_decoder: object = decoded_payload_tags
    finalizer: object = normalize_string_tags
    intrastage_enabled_fn: object = intrastage_enabled
    raw_task_runner: object = run_raw_task_queue
    stage_workers_fn: object = stage_parallel_workers


def scan_strings(request: ScanStringsRequest) -> object:
    """Context-gated string scanner for one immutable dependency request."""
    strings_blob, path, finalize, contextual_scanner, payload_decoder, finalizer, intrastage_enabled_fn, raw_task_runner, stage_workers_fn = request.strings_blob, request.path, request.finalize, request.contextual_scanner, request.payload_decoder, request.finalizer, request.intrastage_enabled_fn, request.raw_task_runner, request.stage_workers_fn
    tags = []
    try:
        if intrastage_enabled_fn() and (len(_strings_text(strings_blob)) >= INTRASTAGE_MIN_TEXT_CHARS):
            local_tasks = []
            _append_intrastage_string_tasks(local_tasks, strings_blob, path=path, source='strings', prefix='scan_strings', include_context=True, include_decode=True)
            if len(local_tasks) > 2:
                stage_results = raw_task_runner(local_tasks, max_workers=stage_workers_fn())
                tags, _m, _s, _e = merge_stage_collector_results(stage_results).as_tuple()
            else:
                tags.extend(contextual_scanner(strings_blob, path=path, source='strings', finalize=False))
                tags.extend(payload_decoder(strings_blob, path=path, finalize=False))
        else:
            tags.extend(contextual_scanner(strings_blob, path=path, source='strings', finalize=False))
            tags.extend(payload_decoder(strings_blob, path=path, finalize=False))
    except SCAN_CONTENT_ERRORS as e:
        try:
            record_suppressed_failure('scanner_string_failure', e, domain='scanner')
        except SCAN_CONTENT_ERRORS:
            tags.append('string_scan_failure_recording_failed')
        tags = scanner_degraded_tags([*tags, 'string_scan_error'])
    if finalize:
        return finalizer(tags, path=path, strings_blob=strings_blob, source='strings')
    return list(tags or [])


def _scan_strings_provider(strings_blob: object, path: object = None, *, finalize: object = True) -> object:
    """Runtime provider using canonical scanner dependencies only."""
    return scan_strings(ScanStringsRequest(strings_blob, path, finalize))



def iter_ordered_string_events(strings_blob: object) -> object:
    """Yield ordered string events from validated contextual tags only."""
    if not strings_blob:
        return
    blob = str(strings_blob)
    blob_l = blob.lower()
    tag_probes = {
        'powershell_exec': ['powershell', 'pwsh'],
        'encoded_powershell': ['encodedcommand', '-enc'],
        'network_download': ['downloadstring', 'downloadfile', 'invoke-webrequest'],
        'url_present': ['http://', 'https://'],
        'mshta_exec': ['mshta'],
        'rundll32_exec': ['rundll32'],
        'regsvr32_exec': ['regsvr32'],
        'memory_write': ['writeprocessmemory', 'ntwritevirtualmemory'],
        'thread_execution': ['createremotethread', 'ntcreatethreadex', 'createthread', 'queueuserapc'],
        'memory_allocate': ['virtualalloc', 'virtualallocex'],
        'credential_dump_attempt': ['mimikatz', 'sekurlsa', 'minidumpwritedump', 'lsass'],
    }
    for tag in contextual_tag_scan(blob, source='timeline'):
        tag_l = str(tag).lower()
        probes = tag_probes.get(tag_l, [tag_l])
        pos = -1
        raw = tag_l
        for needle in probes:
            pos = blob_l.find(needle)
            if pos >= 0:
                raw = blob[pos:pos + len(needle)]
                break
        pos = max(pos, 0)
        yield (pos, {'kind': 'string', 'raw': raw, 'tag': str(tag), 'behavior': primary_behavior_for_tag(tag), 'source': 'contextual_strings'})


__all__ = (
    'INTRASTAGE_CHUNK_CHARS',
    'INTRASTAGE_CHUNK_OVERLAP',
    'INTRASTAGE_MAX_CHUNKS',
    'INTRASTAGE_MIN_TEXT_CHARS',
    'ScanStringsRequest',
    '_append_intrastage_string_tasks',
    '_intrastage_contextual_chunk_raw',
    '_intrastage_decoded_chunk_raw',
    '_raw_stage_scan_strings',
    '_raw_stage_scan_strings_parallel',
    '_split_text_for_intrastage',
    '_umige_ast_enriched_strings',
    'intrastage_contextual_chunk_raw',
    'iter_ordered_string_events',
    'scan_strings',
)
