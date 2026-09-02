"""Projection of pickle embedded payload records into scanner tags."""
from __future__ import annotations

import hashlib

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items, no_hook_text
from Virus_Scan.scanners.contracts import scanner_contract_join
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.pickle.payload_tags import _decoded_payload_exec_tags, _pickle_decoded_payload_tags

_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_DECODE_MAX_OBJECTS = _PICKLE_POLICY.decode_max_objects


def _record_value(rec: object, key: object, default: object = None) -> object:
    items = no_hook_mapping_items(rec, allow_dict_subclass=True)
    if items is None:
        return default
    values = {item_key: item_value for item_key, item_value in items if type(item_key) is str}
    return values.get(key, default)


def _projection_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='missing_pickle_projection_text',
        unsupported_reason='unsafe_pickle_projection_text_rejected',
    )
    return '' if reason else text


def _record_key(rec: object) -> object:
    sha256_text = _projection_text(_record_value(rec, 'sha256', ''))
    if sha256_text:
        return sha256_text
    return hashlib.sha256(_projection_text(_record_value(rec, 'text', '')).encode('utf-8', errors='ignore')).hexdigest()


def _encoding_tags(encoding: object) -> object:
    enc = _projection_text(encoding) or 'pickle_literal'
    if 'zlib' in enc:
        return ['pickle_embedded_zlib_payload', 'zlib_decompress', 'payload_decode_candidate', 'compressed_payload_candidate']
    if 'gzip' in enc:
        return ['pickle_embedded_gzip_payload', 'gzip_decode', 'payload_decode_candidate', 'compressed_payload_candidate']
    if 'base64' in enc:
        return ['pickle_embedded_base64_payload', 'payload_decode_candidate', 'payload_decode_candidate', 'encoded_payload_candidate']
    return []


def _record_payload_tags(rec: object, path: object = None) -> object:
    tags = ['pickle_payload_inspected', 'pickle_embedded_payload_candidate', 'payload_decode_candidate', 'decoded_payload_rescanned']
    tags.extend(_encoding_tags(_record_value(rec, 'encoding')))
    binary_magic = _projection_text(_record_value(rec, 'binary_magic', ''))
    if binary_magic:
        tags.extend(['decoded_binary_payload', scanner_contract_join('decoded_', binary_magic, '_payload')])
    text = _projection_text(_record_value(rec, 'text', ''))
    decoded_tags = _pickle_decoded_payload_tags(text, path=path)
    if decoded_tags:
        tags.extend(decoded_tags)
        tags.extend(_decoded_payload_exec_tags(decoded_tags, text, path=path))
    return tags


def project_embedded_payload_records(records: object, path: object = None) -> object:
    tags = []
    seen = set()
    for rec in no_hook_sequence_items(records)[:PICKLE_DECODE_MAX_OBJECTS]:
        failure_tags = no_hook_sequence_items(_record_value(rec, 'failure_tags', ()))
        if failure_tags:
            tags.extend(failure_tags)
            continue
        key = _record_key(rec)
        if key in seen:
            continue
        seen.add(key)
        if _projection_text(_record_value(rec, 'text', '')):
            tags.extend(_record_payload_tags(rec, path=path))
    return tags


__all__ = ('project_embedded_payload_records',)
