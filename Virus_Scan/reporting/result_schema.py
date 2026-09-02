from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from pathlib import Path, PosixPath, WindowsPath
import hashlib
import json
import os
import re
import time
from Virus_Scan.utils.stages import effective_stage_for_path
from Virus_Scan.runtime.api import durable_replace_regular_file, flush_open_writable_file, log_error
from Virus_Scan.utils.tagging import normalize_tags, norm_lower_set
from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_mapping_items, no_hook_sequence_items, no_hook_text, no_hook_type_name
from Virus_Scan.core.jsonio import deepcopy_jsonable, make_json_safe, verify_persistent_json_file, validate_persistent_record_semantics
from Virus_Scan.core.logging import queue_safe_unlink
from Virus_Scan.core.paths import queue_result_record_name
from Virus_Scan.contracts.result_record import make_worker_error_result as _contract_worker_error_result, make_timeout_result as _contract_timeout_result, normalize_result_record as _normalize_result_record, result_is_cache_reusable as _result_is_cache_reusable, is_passive_fast_asset_result as _contract_is_passive_fast_asset_result, terminal_asset_engine_context
from Virus_Scan.runtime.api import record_suppressed_failure
PLR2004N0_35 = 0.35
PLR2004N0_75 = 0.75
PLR2004N126 = 126
PLR2004N32 = 32
PLR2004N8 = 8

DECODE_LAYER_MAX_TEXT_BYTES = 262144
_RESULT_SCHEMA_PATH_TYPES = (Path, PosixPath, WindowsPath)

def _result_schema_text(value: object, *, default: object='') -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='missing_reporting_result_text',
        unsupported_reason='unsafe_reporting_result_text_rejected',
    )
    if reason:
        return default, reason
    return str.strip(text), ''


def _result_schema_path_text(value: object, *, default: object='') -> object:
    text, reason = _result_schema_text(value, default=default)
    if not reason and text:
        return text, ''
    if type(value) in _RESULT_SCHEMA_PATH_TYPES:
        try:
            return str(value), ''
        except RECOVERABLE_RUNTIME_ERRORS:
            return default, 'path_text_failed'
    return default, reason or 'missing_reporting_result_path'


def _result_schema_lower(value: object, *, default: object='') -> object:
    text, reason = _result_schema_text(value, default=default)
    if reason:
        return default, reason
    return str.lower(text), ''


def _decode_printable_ratio(data: object) -> object:
    try:
        if type(data) not in (bytes, bytearray):
            return 0.0
        sample = bytes(data[:4096])
        if len(sample) == 0:
            return 0.0
        printable = 0
        for b in sample:
            if b in (9, 10, 13) or PLR2004N32 <= b <= PLR2004N126:
                printable += 1
        return printable / max(1, len(sample))
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        _best_effort_record_result_schema_failure('decoded_result_printable_ratio_failed', exc, domain='reporting')
        return 0.0


def _decoded_payload_interesting(text: object, raw_bytes: object=b'') -> object:
    try:
        low, low_reason = _result_schema_lower(text)
        if low_reason:
            low = ''
        if type(raw_bytes) not in (bytes, bytearray):
            raw_bytes = b''
        if raw_bytes.startswith((b'MZ', b'\x7fELF')) or raw_bytes[:4] in (b'PK\x03\x04', b'Rar!'):
            return True
        anchors = ('powershell', 'pwsh', 'encodedcommand', '-enc', 'cmd.exe', 'schtasks', 'certutil', 'bitsadmin', 'mshta', 'rundll32', 'regsvr32', 'wmic', 'invoke-webrequest', 'downloadstring', 'downloadfile', 'frombase64string', 'virtualalloc', 'writeprocessmemory', 'createremotethread', 'ntcreatethreadex', 'mimikatz', 'sekurlsa', 'lsass', 'cryptunprotectdata', 'runonce', 'currentversion\\run', 'http://', 'https://', 'subprocess', 'os.system', 'eval(', 'exec(')
        if any((a in low for a in anchors)):
            return True
        if _decode_printable_ratio(raw_bytes) >= PLR2004N0_75 and any((x in low[:2048] for x in ('import ', 'function ', 'var ', 'const ', 'class ', 'label ', 'define ', 'return'))):
            return True
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        _best_effort_record_result_schema_failure('decoded_payload_interest_check_failed', exc, domain='reporting')
    return False


def _result_schema_mapping_get(mapping: object, key: object, default: object=None) -> object:
    if type(key) is not str:
        return default
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for candidate_key, value in items:
        if type(candidate_key) is str and str.__eq__(candidate_key, key):
            return value
    return default


def _result_schema_text_sequence(value: object, default: object=()) -> object:
    values = no_hook_sequence_items(value)
    if len(values) == 0:
        values = default
    out = []
    for item in values:
        text, reason = _result_schema_text(item)
        if reason:
            continue
        if text:
            out.append(text)
    return out


def _result_schema_string_key_copy(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return {}
    out = {}
    for key, item in items:
        if type(key) is str:
            out[str.__str__(key)] = item
    return out


def _exact_result_mapping(value: object) -> object:
    return value if type(value) is dict else None

def _best_effort_record_result_schema_failure(context: object, exc: object, *, domain: object='reporting', fatal: object=False) -> object:
    try:
        record_suppressed_failure(context, exc, domain=domain, fatal=fatal)
    except RECOVERABLE_RUNTIME_ERRORS as record_exc:
        try:
            context_text, context_reason = _result_schema_text(context, default='result_schema')
            if context_reason:
                context_text = 'result_schema'
            log_error(''.join((context_text, ': failed to record structured failure: ', no_hook_type_name(record_exc))))
        except RECOVERABLE_RUNTIME_ERRORS:
            return False
        return False
    return True

def _best_effort_unlink_queue_path(path: object, *, context: object) -> object:
    try:
        queue_safe_unlink(path, log_context=context)
    except RECOVERABLE_RUNTIME_ERRORS as unlink_exc:
        context_text, context_reason = _result_schema_text(context, default='queue_path')
        if context_reason:
            context_text = 'queue_path'
        _best_effort_record_result_schema_failure(str.__add__(context_text, '_unlink_failed'), unlink_exc, domain='persistence')
        return False
    return True

def _queue_file_results_dir(queue_dir: object) -> object:
    """Reporting result-schema owned durable per-file result directory.

    Stage85: this was imported from reporting.output, creating a reporting
    output/result_schema cycle even though result_schema is the writer owner.
    Keeping the helper here makes output a schemaibility caller only.
    """
    d = Path(queue_dir) / 'file_results'
    try:
        d.mkdir(parents=True, exist_ok=True)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        _best_effort_record_result_schema_failure('queue_file_results_dir_create_failed', exc, domain='reporting')
    return d

def make_terminal_asset_result(path: object, tags: object, prev_stage: object='unknown', curr_stage: object=None, cache_sha256: object='') -> object:
    """Return a complete low-risk result for clean passive assets without running heavy layers."""
    del prev_stage  # Explicitly unused contract parameters.
    path_text, path_reason = _result_schema_path_text(path)
    if path_reason:
        path_text = ''
    source_tags = _result_schema_text_sequence(tags)
    final_tags = normalize_tags([*source_tags, 'terminal_clean_asset_triage', 'fast_path_non_learning'])
    curr_stage_text, curr_stage_reason = _result_schema_text(curr_stage)
    if curr_stage_reason or not curr_stage_text:
        curr_stage_text = effective_stage_for_path(final_tags, path_text)
    cache_text, cache_reason = _result_schema_text(cache_sha256)
    if cache_reason:
        cache_text = ''
    engine_context, active_profile = terminal_asset_engine_context(path_text, final_tags)
    return {'node': path_text, 'file': path_text, 'path': path_text, 'score': 3.0, 'cluster': None, 'class': 'benign_clean', 'classification': 'benign_clean', 'confidence': 0.3, 'tags': final_tags, 'yara_hits': [], 'api': {'api_calls': [], 'ngrams': [], 'call_graph': {}, 'graph_features': {}, 'behavior_timeline': [], 'ordered_events': []}, 'behavior_timeline': [], 'ordered_events': [], 'attack_intelligence': {}, 'heuristics': {'score': 0.0, 'hits': []}, 'layered_detection': {}, 'active_layers': 0, 'layer_weights': {}, 'graph_features': {'risk': 0.0, 'base_risk': 0.0, 'anomaly': 0.0}, 'temporal_features': {'belief': 0.0}, 'markov_features': {'transition': 0.0, 'rarity': 0.0, 'pair_anomaly': 0.0}, 'engine_context': engine_context, 'profile_selection': {'active_profile': active_profile}, 'feature_vector': [], 'fast_path': True, 'learn_eligible': False, 'effective_stage': curr_stage_text, 'suspicious_type_router': False, 'cache_sha256': cache_text, 'explanation': {'classification': 'benign_clean', 'exit_code': 0, 'reasons': ['terminal_clean_asset_triage'], 'fast_path': True, 'learn_eligible': False, 'constraints': {'heavy_layers_skipped': ['full_yara', 'string_rescan', 'api_graph', 'cluster', 'ilspy', 'archive_expand'], 'detection_escalates_on': 'mismatch_or_embedded_script_executable_archive_or_suspicious_tags'}}}

def _scan_cache_clone_result(result: object, current_path: object, sha256: object) -> object:
    """Path-project one already validated current-schema cache record.

    The SQLite repository validates the exact canonical JSON, execution identity,
    result schema, integrity state, and digest before returning a row. Re-running
    result normalization here would create a second semantic construction path and
    can change scanner identity, routing context, or baseline selection on a hit.
    """
    try:
        cloned = deepcopy_jsonable(result if type(result) is dict else {})
    except RECOVERABLE_RUNTIME_ERRORS:
        cloned = _result_schema_string_key_copy(result)
    if type(cloned) is not dict:
        return None
    path_text, path_reason = _result_schema_path_text(current_path)
    if path_reason or not path_text:
        return None
    cloned['file'] = path_text
    cloned['path'] = path_text
    cloned['node'] = path_text
    cloned['cache_sha256'] = sha256
    artifact_read = dict.get(cloned, 'artifact_read')
    if type(artifact_read) is dict:
        projected_artifact_read = dict.copy(artifact_read)
        projected_artifact_read['canonical_path'] = path_text
        cloned['artifact_read'] = projected_artifact_read
    if not _result_is_cache_reusable(cloned):
        return None
    cloned['cache_hit'] = True
    cloned['cache_source'] = 'pre_scan_sha256'
    return cloned

def _umige_passive_fast_cache_without_full_sha(result: object) -> object:
    try:
        result_map = _exact_result_mapping(result)
        if result_map is None:
            return False
        tags = norm_lower_set(dict.get(result_map, 'tags') or [])
        if 'tag_normalization_failure_evidence' in tags:
            return False
        return bool(tags & {'asset_fast_triage_clean', 'image_fast_triage_clean', 'media_asset', 'font_fast_triage_clean', 'passive_asset_fast_triage_clean', 'rpgm_encrypted_asset'})
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        _best_effort_record_result_schema_failure('passive_fast_cache_sha_evidence_failed', exc, domain='reporting')
        return False

def _umige_record_decoded_result(results: object, seen: object, raw: object, encoding: object, cand: object, depth: object, parent: object, chain: object=None) -> object:
    """Build a decoded payload evidence record when the content is worth scanning."""
    try:
        if not raw or len(raw) > DECODE_LAYER_MAX_TEXT_BYTES or len(raw) < PLR2004N8:
            return None
        views = []
        for enc in ('utf-8', 'utf-16le', 'latin1'):
            try:
                txt = raw.decode(enc, errors='ignore')
                if txt and txt not in views:
                    views.append(txt)
            except RECOVERABLE_RUNTIME_ERRORS as _umige_suppressed_exc:
                try:
                    record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
                except RECOVERABLE_RUNTIME_ERRORS as _umige_reporting_exc:
                    _ = _umige_reporting_exc
        if not views:
            return None
        text_view = max(views, key=lambda t: sum((1 for ch in t[:4096] if ch in {'\n', '\t'} or PLR2004N32 <= ord(ch) <= PLR2004N126)))
        if _decode_printable_ratio(raw) < PLR2004N0_35 and (not (raw.startswith((b'MZ', b'\x7fELF', b'PK\x03\x04')))):
            return None
        if not _decoded_payload_interesting(text_view, raw):
            return None
        key = hashlib.sha256(raw).hexdigest()
        if key in seen:
            return None
        seen.add(key)
        parent_text, parent_reason = _result_schema_text(parent)
        if parent_reason:
            parent_text = ''
        cand_text, cand_reason = _result_schema_text(cand)
        if cand_reason:
            cand_text = no_hook_type_name(cand)
        encoding_text, encoding_reason = _result_schema_text(encoding, default='decoded')
        if encoding_reason:
            encoding_text = 'decoded'
        decode_chain = _result_schema_text_sequence(chain, default=(encoding_text,))
        if len(decode_chain) == 0:
            decode_chain = [encoding_text]
        rec = {'encoding': encoding_text, 'depth': depth, 'parent': parent_text, 'parent_sha256': parent_text if re.fullmatch('[0-9a-f]{64}', parent_text) else '', 'raw_sample': cand_text[:96], 'text': text_view[:DECODE_LAYER_MAX_TEXT_BYTES], 'byte_len': len(raw), 'sha256': key, 'evidence_id': str.__add__('decoded:', key[:16]), 'decode_chain': decode_chain, 'binary_magic': 'pe' if raw.startswith(b'MZ') else 'elf' if raw.startswith(b'\x7fELF') else 'zip' if raw.startswith(b'PK\x03\x04') else ''}
        results.append(rec)
        return rec
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        _best_effort_record_result_schema_failure('decoded_result_record_failed', exc, domain='reporting')
        return None

def make_timeout_result(file_path: object, timeout_seconds: object, prev_stage: object='unknown') -> object:
    return _contract_timeout_result(file_path, timeout_seconds, prev_stage=prev_stage)

def _umige_result_is_retryable_file_failure(res: object) -> object:
    try:
        res_map = _exact_result_mapping(res)
        if res_map is None:
            return True
        raw_class = dict.get(res_map, 'class')
        if raw_class is None:
            raw_class = dict.get(res_map, 'classification')
        cls, cls_reason = _result_schema_lower(raw_class)
        err, err_reason = _result_schema_lower(dict.get(res_map, 'error'))
        if cls_reason or err_reason:
            return True
        if dict.get(res_map, 'timed_out') or cls in {'timeout', 'error'}:
            return True
        retry_words = ('timeout', 'temporar', 'file is being used', 'permission', 'access is denied', 'ipc', 'worker', 'queue')
        return bool(err and any((w in err for w in retry_words)))
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        _best_effort_record_result_schema_failure('retryable_file_failure_classification_failed', exc, domain='reporting')
        return True

def _umige_raw_result_has_infra_error(result: object) -> object:
    try:
        if not isinstance(result, dict):
            return True
        return bool(result.get('error'))
    except RECOVERABLE_RUNTIME_ERRORS:
        return True

def _make_worker_error_result(path: object, exc: object) -> object:
    return _contract_worker_error_result(path, exc)

def _verify_queue_file_result_final(final: object, file_path: object) -> object:
    """Verify the durable per-file queue result and fail closed on corruption.

    This is the canonical final verification boundary for queue file result
    publication.  It exists so corrupted final artifacts can be tested directly
    without replacing module globals at runtime.
    """
    try:
        verify = verify_persistent_json_file(final, expected=None, context='queue_file_result_final', require_match=False)
    except RECOVERABLE_RUNTIME_ERRORS as verify_final_exc:
        _best_effort_record_result_schema_failure('queue_file_result_final_verify_failed', verify_final_exc, domain='persistence', fatal=True)
        _best_effort_unlink_queue_path(final, context='queue_file_result_final_verify_failed')
        return False
    if not isinstance(verify, dict):
        _best_effort_unlink_queue_path(final, context='queue_file_result_final_non_mapping')
        return False
    expected_path, expected_reason = _result_schema_path_text(file_path)
    actual_path, actual_reason = _result_schema_text(_result_schema_mapping_get(verify, 'file'))
    if expected_reason or actual_reason or actual_path != expected_path:
        _best_effort_unlink_queue_path(final, context='queue_file_result_final_file_mismatch')
        return False
    if not isinstance(verify.get('result'), dict):
        _best_effort_unlink_queue_path(final, context='queue_file_result_final_result_invalid')
        return False
    verified_result = _normalize_result_record(verify.get('result'), file_path=file_path, source='queue_file_result_verify')
    if verified_result != verify.get('result'):
        _best_effort_unlink_queue_path(final, context='queue_file_result_final_result_not_canonical')
        return False
    return True


def write_queue_file_result(queue_dir: object, claim_path: object, file_path: object, result: object) -> object:
    """Atomically persist one file's scan result and verify it before completion."""
    try:
        d = _queue_file_results_dir(queue_dir)
        final = d / queue_result_record_name(claim_path, file_path)
        tmp = d / (final.name + '.tmp')
        file_text, file_reason = _result_schema_path_text(file_path)
        if file_reason:
            file_text = ''
        claim_text, claim_reason = _result_schema_path_text(claim_path)
        claim_name = Path(claim_text).name if not claim_reason and claim_text else None
        payload = {'file': file_text, 'result': make_json_safe(_normalize_result_record(result, file_path=file_path, source='queue_file_result')), 'claim': claim_name, 'worker_pid': os.getpid(), 'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        sync_ok = True
        try:
            validate_persistent_record_semantics(payload, context='queue_file_result_expected')
        except RECOVERABLE_RUNTIME_ERRORS as semantic_exc:
            _best_effort_record_result_schema_failure('queue_file_result_semantic_validation_failed', semantic_exc, domain='persistence', fatal=True)
            return False
        with Path(tmp).open('w', encoding='utf-8') as fh:
            json.dump(payload, fh, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
            try:
                fh.flush()
                flush_open_writable_file(fh.fileno())
            except RECOVERABLE_RUNTIME_ERRORS as _umige_suppressed_exc:
                sync_ok = False
                try:
                    record_suppressed_failure('queue_file_result_sync_failed', _umige_suppressed_exc, domain='persistence', fatal=True)
                except RECOVERABLE_RUNTIME_ERRORS as _umige_reporting_exc:
                    _ = _umige_reporting_exc
        if not sync_ok:
            _best_effort_unlink_queue_path(tmp, context='queue_file_result_sync_failed')
            return False
        try:
            verify_persistent_json_file(tmp, expected=payload, context='queue_file_result_tmp', require_match=True)
        except RECOVERABLE_RUNTIME_ERRORS as verify_tmp_exc:
            _best_effort_record_result_schema_failure('queue_file_result_tmp_verify_failed', verify_tmp_exc, domain='persistence', fatal=True)
            _best_effort_unlink_queue_path(tmp, context='queue_file_result_tmp_verify_failed')
            return False
        try:
            durable_replace_regular_file(Path(tmp), Path(final))
        except RECOVERABLE_RUNTIME_ERRORS as replace_exc:
            _best_effort_record_result_schema_failure(
                'queue_file_result_replace_failed',
                replace_exc,
                domain='persistence',
                fatal=True,
            )
            _best_effort_unlink_queue_path(tmp, context='queue_file_result_replace_failed')
            return False
        return _verify_queue_file_result_final(final, file_path)
    except RECOVERABLE_RUNTIME_ERRORS as e:
        try:
            file_text, file_reason = _result_schema_path_text(file_path, default='unknown_file')
            if file_reason:
                file_text = 'unknown_file'
            log_error(''.join(('queue file result persist failed for ', file_text, ': ', no_hook_type_name(e))))
        except RECOVERABLE_RUNTIME_ERRORS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except RECOVERABLE_RUNTIME_ERRORS as _umige_reporting_exc:
                _ = _umige_reporting_exc
        return False

def _umige_cancel_result(path: object, reason: object='cancelled_generation') -> object:
    reason_text, reason_text_failure = _result_schema_text(reason, default='cancelled_generation')
    if reason_text_failure or not reason_text:
        reason_text = 'cancelled_generation'
    try:
        res = _make_worker_error_result(path, RuntimeError(reason_text))
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        res = _contract_worker_error_result(path, ''.join((reason_text, '; cancel-result constructor failed: ', no_hook_type_name(exc))))
    try:
        if isinstance(res, dict):
            res['queue_failure'] = True
            res['scheduler_failure_reason'] = reason_text
            res['cancelled_generation'] = True
    except RECOVERABLE_RUNTIME_ERRORS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except RECOVERABLE_RUNTIME_ERRORS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    return (path, res)

__all__ = ('_make_worker_error_result', '_scan_cache_clone_result', '_umige_cancel_result', '_umige_raw_result_has_infra_error', '_umige_record_decoded_result', '_umige_result_is_passive_fast_asset_result', '_umige_result_is_retryable_file_failure', 'write_queue_file_result', 'make_terminal_asset_result', 'make_timeout_result')
_umige_result_is_passive_fast_asset_result = _contract_is_passive_fast_asset_result
