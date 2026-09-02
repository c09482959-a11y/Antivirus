"""Pickle embedded byte-view scanning and payload-record collection."""
from __future__ import annotations

import hashlib

from Virus_Scan.runtime.api import is_programmer_error, scanner_failure_tags
from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scanners.contracts import scanner_contract_join, scanner_contract_text
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.pickle.graph_tags import pickle_opcode_graph_tags
from Virus_Scan.scanners.pickle.literals import _iter_pickle_fragment_decode_records_from_analysis
from Virus_Scan.scanners.pickle.opcode_analysis import analyze_pickle_opcode_graph
from Virus_Scan.scanners.pickle.payload_records import _iter_pickle_payload_records, _iter_raw_compressed_payload_records
from Virus_Scan.scanners.pickle.rpyc_views import _iter_rpyc_pickle_byte_views

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError
)
_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_DECODE_MAX_OFFSETS = _PICKLE_POLICY.decode_max_offsets


def _payload_stream_limit(ext: object) -> object:
    return 96 if ext == '.rpa' else PICKLE_DECODE_MAX_OFFSETS


def _deduped_payload_views(blob: object, path: object, tags: object) -> object:
    try:
        graph_payloads = list(_iter_rpyc_pickle_byte_views(blob, path=path))
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        if is_programmer_error(exc):
            raise
        tags.extend(scanner_failure_tags('pickle_embedded_payload_tags.byte_views', exc, ['pickle_byte_view_scan_error']))
        graph_payloads = [('raw', blob)]
    seen_payloads = set()
    for enc_kind, payload_blob in graph_payloads:
        digest = hashlib.sha256(bytes(payload_blob[:4096])).hexdigest()
        if digest in seen_payloads:
            continue
        seen_payloads.add(digest)
        yield enc_kind, payload_blob


def _append_stream_context_tags(tags: object, enc_kind: object, graph_tags: object) -> object:
    if enc_kind == 'raw' or not graph_tags:
        return
    enc_text = scanner_contract_text(enc_kind, replacement='')
    tags.append('rpyc_decoded_stream_inspected')
    if enc_text.startswith('rpa_member:'):
        tags.append('rpa_member_pickle_stream')
        if 'script.rpyc' in enc_text.lower():
            tags.append('rpa_member_script_rpyc_pickle_stream')
    else:
        tags.append(scanner_contract_join(enc_text, '_pickle_stream'))


def _append_graph_tags(tags: object, graph_tags: object, has_pickle_container_magic: object) -> object:
    if not graph_tags:
        return
    low_graph_tags = {
        scanner_contract_text(tag, replacement='').lower()
        for tag in no_hook_sequence_items(graph_tags)
        if scanner_contract_text(tag, replacement='')
    }
    if has_pickle_container_magic and {'pickle_dangerous_global', 'pickle_callable_reference', 'pickle_reduce_opcode'} <= low_graph_tags:
        graph_tags = [*list(graph_tags), 'renpy', 'renpy_script']
    tags.extend(graph_tags)


def _collect_payload_records(payload_blob: object) -> object:
    analysis = analyze_pickle_opcode_graph(payload_blob)
    records = list(_iter_pickle_fragment_decode_records_from_analysis(analysis) or [])
    records.extend(list(_iter_pickle_payload_records(payload_blob) or []))
    records.extend(list(_iter_raw_compressed_payload_records(payload_blob) or []))
    return records


def collect_embedded_payload_records(blob: object, path: object, ext: object, has_pickle_container_magic: object, tags: object) -> object:
    records = []
    for enc_kind, payload_blob in list(_deduped_payload_views(blob, path, tags))[:_payload_stream_limit(ext)]:
        try:
            graph_tags = pickle_opcode_graph_tags(payload_blob, path=path)
            _append_stream_context_tags(tags, enc_kind, graph_tags)
            _append_graph_tags(tags, graph_tags, has_pickle_container_magic)
            records.extend(_collect_payload_records(payload_blob))
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
            if is_programmer_error(exc):
                raise
            tags.extend(scanner_failure_tags('pickle_embedded_payload_tags.payload', exc, ['pickle_payload_scan_error']))
    return records


__all__ = ('collect_embedded_payload_records',)
