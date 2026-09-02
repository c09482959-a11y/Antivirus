import hashlib
import json
import math
import os
import secrets
import shutil
import threading
import time
from pathlib import Path, PurePath
from threading import RLock

from Virus_Scan.contracts.env_config import int_env
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_json_sort_key,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.contracts.result_record import validate_result_record_invariants as _contract_validate_result_record_invariants, validate_result_collection_invariants as _contract_validate_result_collection_invariants
from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.core.logging import queue_safe_unlink
from Virus_Scan.core.paths import _umige_runtime_temp_dir, _queue_failure_diagnostics_dir
from Virus_Scan.core.path_utils import core_path_text
from Virus_Scan.core.jsonio_queue_failure_support import (
    queue_failure_claim_text,
    queue_failure_payload,
    merge_queue_failure_job,
    queue_failure_error_info,
    rewrite_queue_failure_claim,
    write_queue_failure_diagnostic,
)
from Virus_Scan.runtime.immutable_core import freeze_runtime_value
from Virus_Scan.runtime.api import (
    FilesystemDurabilityError,
    durable_replace_regular_file,
    flush_directory,
    flush_open_writable_file,
    path_contains_filesystem_alias,
)
from Virus_Scan.runtime.init_state import get_init_value
from Virus_Scan.runtime.resource_paths import program_root
from Virus_Scan.runtime.structured_failures import record_suppressed_failure, safe_exception_message
from Virus_Scan.utils.tagging import normalize_tags
JSON_PERSISTENCE_EXCEPTIONS = (
    OSError,
    FilesystemDurabilityError,
    ValueError,
    TypeError,
    json.JSONDecodeError,
)
JSON_TELEMETRY_EXCEPTIONS = (OSError, RuntimeError, ValueError, TypeError)
JSON_SAVE_LOCK = RLock()
_RLOCK_TYPE = type(JSON_SAVE_LOCK)
ATOMIC_JSON_VERIFY_MAX_BYTES = 16 * 1024 * 1024
_BASE_DIR_VALUE = get_init_value('BASE_DIR')
_BASE_DIR_TEXT, _BASE_DIR_REASON = no_hook_text(
    _BASE_DIR_VALUE,
    missing_reason='base_dir_missing',
    unsupported_reason='base_dir_rejected',
)
BASE_DIR = _BASE_DIR_TEXT if not _BASE_DIR_REASON and _BASE_DIR_TEXT else PurePath.__str__(program_root())


def _jsonio_status(recorded: object, where: object, exc: object=None) -> object:
    where_text, where_reason = no_hook_text(
        where,
        missing_reason='jsonio_status_where_missing',
        unsupported_reason='jsonio_status_where_rejected',
    )
    out = {
        'recorded': recorded is True,
        'where': where_text if not where_reason and where_text else 'jsonio_status_where_unavailable',
    }
    if exc is not None:
        out['error_type'] = no_hook_type_name(exc)
    return out


def _jsonio_exception_text(prefix: object, exc: object) -> object:
    detail = safe_exception_message(exc)
    error_type = no_hook_type_name(exc)
    if detail and detail != error_type:
        return str.__add__(prefix, str.__add__(error_type, str.__add__(": ", detail)))
    return str.__add__(prefix, error_type)


def _jsonio_index_text(prefix: object, index: object) -> object:
    return str.__add__(prefix, int.__str__(index))





_DOTNET_DYNAMIC_LOADER_VALUES = no_hook_sequence_items(get_init_value('DOTNET_DYNAMIC_LOADER_TAGS'))
DOTNET_DYNAMIC_LOADER_TAGS = frozenset(normalize_tags(_DOTNET_DYNAMIC_LOADER_VALUES)) or frozenset({'dotnet_reflective_loader', 'assembly_load', 'reflection_invoke', 'dynamic_method'})
_DOTNET_DYNAMIC_LOADER_PAYLOAD_VALUES = no_hook_sequence_items(get_init_value('DOTNET_DYNAMIC_LOADER_PAYLOAD_TAGS'))
DOTNET_DYNAMIC_LOADER_PAYLOAD_TAGS = frozenset(normalize_tags(_DOTNET_DYNAMIC_LOADER_PAYLOAD_VALUES)) or frozenset({'embedded_pe_payload', 'decoded_pe_payload', 'in_memory_execution', 'dotnet_reflective_loader'})

def _jsonio_record_degraded(where: object, exc: object, *, domain: object='persistence') -> object:
    """Best-effort telemetry boundary for JSON persistence degradation.

    This is intentionally non-recursive: telemetry failures must not mask the
    original persistence outcome or introduce secondary recovery behavior.
    """
    recorded = True
    telemetry_failure = None
    try:
        record_suppressed_failure(where, exc, domain=domain)
    except JSON_TELEMETRY_EXCEPTIONS as telemetry_exc:
        recorded = False
        telemetry_failure = telemetry_exc
    return _jsonio_status(recorded, where, telemetry_failure)

def _jsonio_log_degraded(message: object) -> object:
    """Best-effort logging boundary without silent pass blocks."""
    recorded = True
    telemetry_failure = None
    try:
        log_error(message)
    except JSON_TELEMETRY_EXCEPTIONS as telemetry_exc:
        recorded = False
        telemetry_failure = telemetry_exc
    return _jsonio_status(recorded, 'jsonio_log_degraded', telemetry_failure)


def _json_safe_order_key(value: object) -> object:
    """Return a deterministic ordering key for JSON-safe set members without caller hooks."""
    return (no_hook_type_name(value), no_hook_json_sort_key(value))


def _jsonio_safe_text(value: object, *, replacement: object='') -> object:
    """Return boundary text without truthiness, stringification, or property hooks."""
    text, reason = no_hook_text(
        value,
        missing_reason='missing_jsonio_text',
        unsupported_reason='unsafe_jsonio_text_value_rejected',
    )
    if reason or text == '':
        replacement_text, replacement_reason = no_hook_text(
            replacement,
            missing_reason='missing_jsonio_text_default',
            unsupported_reason='unsafe_jsonio_text_default_rejected',
        )
        return '' if replacement_reason else str.strip(replacement_text)
    return str.strip(text)


def _jsonio_context_text(context: object) -> object:
    text, reason = no_hook_text(
        context,
        missing_reason='jsonio_context_missing',
        unsupported_reason='jsonio_context_rejected',
    )
    if reason or text == '':
        return str.__add__('jsonio_context_rejected:', no_hook_type_name(context))
    return str.strip(text)


def _jsonio_context_message(context: object, message: object) -> object:
    return str.__add__(_jsonio_context_text(context), str.__add__(': ', message))


def _jsonio_context_child(context: object, child: object) -> object:
    child_text, child_reason = no_hook_text(
        child,
        missing_reason='jsonio_child_context_missing',
        unsupported_reason='jsonio_child_context_rejected',
    )
    if child_reason or child_text == '':
        child_text = no_hook_type_name(child)
    return str.__add__(_jsonio_context_text(context), str.__add__(':', child_text))


def _jsonio_unsupported_value(value: object, *, field_name: object='jsonio_value', reason: object='unsupported_jsonio_value') -> object:
    field = _jsonio_safe_text(field_name, replacement='jsonio_value') or 'jsonio_value'
    return {
        'value': None,
        'unavailable_reason': reason,
        'field': field,
        'value_type': no_hook_type_name(value),
    }


def _jsonio_stdlib_path_text(value: object) -> object:
    if not isinstance(value, PurePath):
        return None
    module = type(value).__module__
    if type(module) is not str or not str.__str__(module).startswith('pathlib'):
        return None
    return PurePath.__str__(value)


def _download_meta_path(dest: object) -> object:
    """Return the YARA download metadata path owned by the downloaded artifact."""
    text, reason = core_path_text(dest, field_name='download_destination')
    if reason:
        raise ValueError(reason)
    p = Path(text)
    parent = p.parent if p.parent else Path('.')
    return PurePath.__str__(parent / (p.name + '.meta.json'))

def _umige_unique_json_tmp_path(path: object) -> object:
    """Unique JSON temp path on the destination volume.

    ``os.replace`` is only atomic within one filesystem on Windows.  Keep valid
    destination writes in the destination directory so profile/report writes to
    caller-owned temp roots do not fail as cross-volume moves.  Runtime-owned
    profile paths use the scanner-owned runtime Temp directory, which is under
    the same runtime root and avoids transient JSON artifacts in ``profiles``.
    Malformed paths still fall back to runtime Temp, avoiding the older
    root-level ``None.tmp`` artifacts.
    """
    if path is None:
        path_text, path_reason = 'umige.json', ''
    else:
        path_text, path_reason = core_path_text(path, field_name='json_destination')
    if path_reason:
        _jsonio_record_degraded(
            'json_tmp_destination_path_rejected',
            ValueError(path_reason),
            domain='persistence',
        )
        path_text = 'umige.json'
    try:
        base = Path(path_text).name or 'umige.json'
    except JSON_PERSISTENCE_EXCEPTIONS:
        base = 'umige.json'
    safe_base = ''.join((ch if ch.isalnum() or ch in '._-' else '_' for ch in base)).strip('._ ')
    if not safe_base:
        safe_base = 'umige.json'
    try:
        tid = threading.get_ident()
    except JSON_PERSISTENCE_EXCEPTIONS:
        tid = 0
    try:
        nonce = str.__add__(int.__str__(time.time_ns()), str.__add__('_', int.__str__(secrets.randbelow(2147483648))))
    except JSON_PERSISTENCE_EXCEPTIONS:
        nonce = int.__str__(os.getpid())
    tmp_name = str.__add__(
        safe_base,
        str.__add__('.tmp.', str.__add__(int.__str__(os.getpid()), str.__add__('.', str.__add__(int.__str__(tid), str.__add__('.', nonce))))),
    )
    try:
        raw_path = '' if path is None or path_reason else path_text.strip()
        if raw_path and raw_path.lower() not in {'none', 'null'}:
            parent = Path(str(Path(raw_path).resolve())).parent
            runtime_temp = Path(_umige_runtime_temp_dir()).resolve()
            runtime_profiles = (runtime_temp.parent / 'profiles').resolve()
            try:
                if parent.resolve() == runtime_profiles:
                    return str(runtime_temp / tmp_name)
            except JSON_PERSISTENCE_EXCEPTIONS as profile_tmp_exc:
                _jsonio_record_degraded('json_tmp_runtime_profile_root_check_failed', profile_tmp_exc, domain='persistence')
            if PurePath.__str__(parent):
                Path(parent).mkdir(parents=True, exist_ok=True)
                return PurePath.__str__(parent / tmp_name)
    except JSON_PERSISTENCE_EXCEPTIONS as tmp_exc:
        _jsonio_record_degraded('json_tmp_destination_parent_unavailable', tmp_exc, domain='persistence')
    return PurePath.__str__(_umige_runtime_temp_dir() / tmp_name)

def deepcopy_jsonable(obj: object) -> object:
    try:
        return json.loads(json.dumps(make_json_safe(obj), allow_nan=False))
    except JSON_PERSISTENCE_EXCEPTIONS as exc:
        _jsonio_record_degraded('deepcopy_jsonable_materialization_failed', exc, domain='persistence')
        return _jsonio_unsupported_value(
            obj,
            field_name='deepcopy_jsonable',
            reason='json_materialization_failed',
        )

def _dotnet_dynamic_loader_valid(evidence: object, cats: object, *, hard_anchor: object=False) -> object:
    """Unity/.NET dynamic loading is normal until paired with payload/deserialize/in-memory/C2/injection."""
    evidence_values = no_hook_sequence_items(evidence)
    if evidence is not None and not evidence_values and type(evidence) not in (tuple, list, set, frozenset, str, bytes, bytearray, int, float, bool):
        return (False, 'dotnet_dynamic_loader_evidence_rejected')
    evidence_tags = frozenset(normalize_tags(evidence_values))
    cat_items = no_hook_mapping_items(cats)
    if cat_items is None:
        return (False, 'dotnet_dynamic_loader_categories_rejected')
    category_values = {key: value for key, value in cat_items if type(key) is str}
    execute = dict.get(category_values, 'execute') is True
    injection = dict.get(category_values, 'injection') is True
    hard = hard_anchor is True
    loader = bool(evidence_tags & DOTNET_DYNAMIC_LOADER_TAGS)
    payload = bool(evidence_tags & DOTNET_DYNAMIC_LOADER_PAYLOAD_TAGS)
    risky_loader = bool(evidence_tags & {'binary_deserialize', 'dynamic_method', 'reflection_dotnet'})
    if loader and payload and (execute or injection or hard or bool(evidence_tags & {'in_memory_execution', 'embedded_pe_payload', 'confirmed_embedded_pe_payload'})):
        return (True, 'validated_dotnet_dynamic_loader_with_payload_or_memory_context')
    if risky_loader and (dict.get(category_values, 'c2') is True or hard or bool(evidence_tags & {'process_injection', 'thread_execution', 'memory_write'})):
        return (True, 'validated_dotnet_dynamic_loader_with_c2_or_injection_context')
    return (False, 'dotnet_dynamic_loader_report_only_without_payload_memory_or_c2')


def _normalize_persistent_record_schema(value: object, *, default_schema_version: object=1) -> object:
    """Normalize schema metadata for queue/result/failure records before write.

    Stage79: historical serializers sometimes wrote operational records
    without schema_version, leaving recovery/replay code to infer mismatched
    shapes.  Only records with queue/failure/result semantics are normalized;
    arbitrary payloads are left untouched.
    """
    value_items = no_hook_mapping_items(value)
    if value_items is None:
        return value
    out = dict(value_items)
    schema_default, schema_default_reason = no_hook_exact_nonnegative_int(
        default_schema_version,
        default=1,
    )
    if schema_default_reason or schema_default == 0:
        schema_default = 1
    semantic_keys = {'job_type', 'failure_info', 'queue_info', 'queue_identity', 'record_type', 'result', 'results', 'file', 'file_id', 'quarantined', 'error_info', 'scan_result'}
    if 'schema_version' not in out and any((k in out for k in semantic_keys)):
        out['schema_version'] = schema_default
    if 'schema_version' in out:
        schema_version, schema_reason = no_hook_exact_nonnegative_int(
            dict.get(out, 'schema_version'),
            default=schema_default,
        )
        out['schema_version'] = schema_default if schema_reason or schema_version == 0 else schema_version
    return out

def validate_persistent_record_semantics(value: object, *, context: object='persistent_json') -> object:
    """Validate semantic completeness for durable operational JSON records.

    Readability alone is not enough at queue/replay boundaries: a truncated but
    syntactically valid object can otherwise resurrect as durable state.  This
    validator intentionally applies only to records that advertise queue,
    failure, result, cache, or replay semantics so arbitrary diagnostic JSON is
    not over-constrained.
    """
    value_items = no_hook_mapping_items(value)
    if value_items is None:
        if value is None or type(value) in (str, bytes, bytearray, bool, int, float, list, tuple):
            return True
        raise TypeError(_jsonio_context_message(context, 'persistent record mapping rejected'))
    value = dict(value_items)
    if type(value) is not dict:
        return True
    semantic_keys = {'queue_failure', 'failure_info', 'queue_info', 'queue_identity', 'job_type', 'record_type', 'result', 'results', 'scan_result', 'file', 'file_path', 'path', 'file_id', 'schema_version', 'entries', 'fast_entries', 'replay', 'replay_events'}
    if not any((k in value for k in semantic_keys)):
        return True
    if value.get('queue_failure') is True:
        fi = value.get('failure_info')
        if type(fi) is not dict or not fi:
            raise ValueError(_jsonio_context_message(context, 'queue_failure record missing non-empty failure_info'))
        if not any((fi.get(k) for k in ('error', 'exception_type', 'stage', 'message'))):
            raise ValueError(_jsonio_context_message(context, 'failure_info lacks causal error metadata'))
    if 'failure_info' in value and value.get('failure_info') is not None:
        if type(value.get('failure_info')) is not dict:
            raise ValueError(_jsonio_context_message(context, 'failure_info must be an object'))
    for key in ('result', 'scan_result'):
        if key in value and value.get(key) is not None and type(value.get(key)) is not dict:
            raise ValueError(_jsonio_context_message(context, str.__add__(key, ' must be an object')))
        if key in value and type(value.get(key)) is dict:
            nested_items = no_hook_mapping_items(dict.get(value, key))
            if nested_items is None:
                raise ValueError(_jsonio_context_message(context, str.__add__(key, ' must be an object')))
            nested = dict(nested_items)
            if not (nested.get('file') or nested.get('path') or nested.get('node')) and (value.get('file') or value.get('path') or value.get('node')):
                nested.setdefault('file', value.get('file') or value.get('path') or value.get('node'))
            if any((k in nested for k in ('classification', 'class', 'verdict', 'score', 'error', 'timed_out', 'queue_failure'))):
                _contract_validate_result_record_invariants(nested, context=_jsonio_context_child(context, key))
    if any((k in value for k in ('classification', 'class', 'verdict', 'score'))) and any((k in value for k in ('file', 'path', 'node'))):
        _contract_validate_result_record_invariants(value, context=_jsonio_context_child(context, 'result'))
    if 'results' in value and value.get('results') is not None:
        _contract_validate_result_collection_invariants(value, context=_jsonio_context_child(context, 'results'))
    if 'entries' in value or 'fast_entries' in value:
        if type(value.get('entries', {})) is not dict:
            raise ValueError(_jsonio_context_message(context, 'entries must be an object'))
        if type(value.get('fast_entries', {})) is not dict:
            raise ValueError(_jsonio_context_message(context, 'fast_entries must be an object'))
    if any((k in value for k in ('queue_info', 'queue_identity'))):
        if not any((value.get(k) for k in ('file', 'file_path', 'path', 'file_id', 'queue_identity'))):
            raise ValueError(_jsonio_context_message(context, 'queue job record lacks file identity'))
    return True

def verify_persistent_json_file(path: object, expected: object=None, *, context: object='persistent_json', require_match: object=False) -> object:
    """Read back and validate durable JSON after publication."""
    path_text, path_reason = core_path_text(path, field_name='persistent_json_path')
    if path_reason:
        raise ValueError(path_reason)
    with Path(path_text).open('r', encoding='utf-8') as fh:
        loaded = json.load(fh)
    validate_persistent_record_semantics(loaded, context=context)
    if require_match and expected is not None and (loaded != expected):
        raise ValueError(_jsonio_context_message(context, 'readback mismatch after publication'))
    return loaded



def _read_download_meta(dest: object, *, download_meta_path: object=_download_meta_path) -> object:
    """Read YARA download metadata without hiding corrupt persisted state.

    Corrupt download metadata used to fall through to ``{}``, making cache
    freshness/recovery treat a damaged state file as a normal cache miss.  That
    is a false-success suppression at the cache boundary: the caller loses the
    forensic fact that persisted state was corrupt.  Preserve runtime
    the prior empty-object behavior, but first quarantine the bad JSON and
    record a typed suppressed-failure event.
    """
    meta_path = None
    dest_text, dest_reason = core_path_text(dest, field_name='download_destination')
    if dest_reason:
        _jsonio_record_degraded(
            'yara_download_meta_path_rejected',
            ValueError(dest_reason),
            domain='yara',
        )
        return {}
    try:
        meta_path = download_meta_path(dest_text)
        if Path(meta_path).exists():
            with Path(meta_path).open('r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
            try:
                _quarantine_corrupt_json_file(meta_path, reason='download metadata root is not an object', log_context='yara_download_meta')
            except JSON_PERSISTENCE_EXCEPTIONS as telemetry_exc:
                _jsonio_record_degraded('jsonio_telemetry_record_failed', telemetry_exc, domain='telemetry')
            return {}
    except json.JSONDecodeError as _umige_suppressed_exc:
        try:
            if meta_path:
                _quarantine_corrupt_json_file(meta_path, reason=_jsonio_exception_text('download metadata JSON decode failed: ', _umige_suppressed_exc), log_context='yara_download_meta')
        except JSON_PERSISTENCE_EXCEPTIONS as telemetry_exc:
            _jsonio_record_degraded('jsonio_telemetry_record_failed', telemetry_exc, domain='telemetry')
        try:
            record_suppressed_failure('yara_download_meta_corrupt', _umige_suppressed_exc, domain='yara')
        except JSON_PERSISTENCE_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    except JSON_PERSISTENCE_EXCEPTIONS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except JSON_PERSISTENCE_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    return {}

def _record_json_read_failure(where: object, exc: object, *, domain: object='persistence') -> None:
    """Record JSON read/semantic failures without making read paths recursive."""
    _jsonio_record_degraded(where, exc, domain=domain)

def _json_read_retry_requested(path_text: str, attempt: int, retries: int) -> bool:
    try:
        ps = path_text.lower()
        return (
            'umige_process_queue' in ps
            or '\\queue\\' in ps
            or '/queue/' in ps
            or str(ps).endswith('.tmp')
        ) and attempt < retries - 1
    except JSON_PERSISTENCE_EXCEPTIONS:
        return attempt < retries - 1


def _json_read_attempt(
    path_text: str,
    default: object,
    *,
    attempt: int,
    retries: int,
) -> tuple[bool, object, object | None, str, bool]:
    try:
        with Path(path_text).open('r', encoding='utf-8', errors='strict') as fh:
            data = json.load(fh)
        try:
            validate_persistent_record_semantics(
                data,
                context=str.__add__('read_json_file:', Path(path_text).name),
            )
        except JSON_PERSISTENCE_EXCEPTIONS as semantic_exc:
            _record_json_read_failure(
                'json_read_semantic_validation_failed',
                semantic_exc,
                domain='persistence',
            )
            return True, default if default is not None else {}, semantic_exc, 'semantic', False
        return True, data, None, 'read', False
    except (UnicodeDecodeError, PermissionError, OSError, json.JSONDecodeError, ValueError) as exc:
        stage = 'decode' if isinstance(exc, (UnicodeDecodeError, json.JSONDecodeError, ValueError)) else 'io'
        return False, None, exc, stage, _json_read_retry_requested(path_text, attempt, retries)
    except JSON_PERSISTENCE_EXCEPTIONS as exc:
        return False, None, exc, 'unexpected', False


def read_json_file(path: object, default: object=None) -> object:
    """Read JSON with retry, semantic validation, and forensic attribution.

    Queue and replay jobs are published by atomic rename, but immediately after a
    rename Windows/Sandboxie/AV can still hold a transient read lock.  Earlier
    builds correctly retried transient read errors but still returned any
    syntactically valid JSON object, even when the object was semantically
    incomplete for queue/replay/cache use.  Batch 5 makes this reader fail
    closed at operational JSON boundaries: readable-but-invalid durable state is
    not returned to recovery/replay callers as usable state.
    """
    retries = int_env('UMIGE_QUEUE_JSON_READ_RETRIES', 6, 1, None)
    path_text, path_reason = core_path_text(path, field_name='json_read_path')
    if path_reason:
        failure = ValueError(path_reason)
        _record_json_read_failure('json_read_path_rejected', failure, domain='persistence')
        return default if default is not None else {
            'value': None,
            'unavailable_reason': path_reason,
            'value_type': no_hook_type_name(path),
        }
    last_exc = None
    last_stage = 'read'
    for i in range(retries):
        finished, payload, last_exc, last_stage, should_retry = _json_read_attempt(
            path_text,
            default,
            attempt=i,
            retries=retries,
        )
        if finished:
            return payload
        if should_retry:
            time.sleep(min(0.25, 0.025 * (i + 1)))
            continue
        break
    if last_exc is not None:
        _record_json_read_failure(str.__add__('json_read_', str.__add__(last_stage, '_failed')), last_exc, domain='persistence')
    return default if default is not None else {}


def _jsonio_queue_failure_info(stage: object, *, exception_type: object='QueueFailure', error: object='queue job failed', worker_pid: object=None, attempt: object=None, extra: object=None) -> object:
    """Build canonical queue failure diagnostics at the JSON persistence boundary."""
    info: dict[str, object] = {
        'stage': _jsonio_safe_text(stage, replacement='queue_failed') or 'queue_failed',
        'exception_type': _jsonio_safe_text(exception_type, replacement='QueueFailure') or 'QueueFailure',
        'error': _jsonio_safe_text(error, replacement='queue job failed') or 'queue job failed',
        'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    if worker_pid is not None:
        info['worker_pid'] = make_json_safe(worker_pid, 'worker_pid')
    if attempt is not None:
        info['attempt'] = make_json_safe(attempt, 'attempt')
    extra_items = no_hook_mapping_items(extra)
    if extra_items is not None:
        for index, (key, value) in enumerate(extra_items):
            replacement_key = _jsonio_index_text('extra_', index)
            key_text = _jsonio_safe_text(key, replacement=replacement_key) or replacement_key
            if key_text not in info:
                info[key_text] = make_json_safe(value, key_text)
    elif extra is not None:
        info['extra_unavailable'] = _jsonio_unsupported_value(
            extra,
            field_name='queue_failure_extra',
            reason='unsupported_queue_failure_extra',
        )
    return info

def _record_process_queue_failure(queue_dir: object, claim_path: object, job: object=None, error_info: object=None) -> object:
    """Persist infrastructure failure context before a queue job is moved.

    This is diagnostic only. It never adds tags and never contributes to score.
    Returns True only after the claim JSON was rewritten with failure_info.
    """
    claim_text = queue_failure_claim_text(
        claim_path,
        core_path_text=core_path_text,
        record_degraded=_jsonio_record_degraded,
    )
    if claim_path is not None and claim_text is None:
        return False
    try:
        payload = queue_failure_payload(claim_text, read_json=read_json_file)
        merge_queue_failure_job(
            payload,
            job,
            mapping_items=no_hook_mapping_items,
            unsupported_value=_jsonio_unsupported_value,
        )
        error_info = queue_failure_error_info(
            payload,
            error_info,
            mapping_items=no_hook_mapping_items,
            queue_failure_info=_jsonio_queue_failure_info,
            unsupported_value=_jsonio_unsupported_value,
            make_json_safe_func=make_json_safe,
            time_module=time,
        )
        payload['queue_failure'] = True
        payload['failure_info'] = make_json_safe(error_info)
        ok = True
        if claim_text is not None:
            ok = rewrite_queue_failure_claim(
                claim_text,
                payload,
                json_module=json,
                open_func=open,
                normalize_record=_normalize_persistent_record_schema,
                make_json_safe_func=make_json_safe,
                read_json=read_json_file,
                safe_unlink=queue_safe_unlink,
                record_degraded=_jsonio_record_degraded,
                record_suppressed=record_suppressed_failure,
                persistence_exceptions=JSON_PERSISTENCE_EXCEPTIONS,
            )
            if ok is False:
                return False
        return write_queue_failure_diagnostic(
            queue_dir,
            claim_text,
            payload,
            json_module=json,
            open_func=open,
            path_cls=Path,
            diagnostics_dir=_queue_failure_diagnostics_dir,
            make_json_safe_func=make_json_safe,
            safe_unlink=queue_safe_unlink,
            record_degraded=_jsonio_record_degraded,
            record_suppressed=record_suppressed_failure,
            time_module=time,
            persistence_exceptions=JSON_PERSISTENCE_EXCEPTIONS,
            prior_ok=ok,
        )
    except JSON_PERSISTENCE_EXCEPTIONS as e:
        try:
            log_error(_jsonio_exception_text('queue failure diagnostic write failed: ', e))
        except JSON_PERSISTENCE_EXCEPTIONS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except JSON_PERSISTENCE_EXCEPTIONS as _umige_reporting_exc:
                _ = _umige_reporting_exc
        raise

def _umige_json_lock_path(path: object) -> object:
    """Return a Sandboxie-safe lock path under <script/exe root>\\Temp.

    Older builds created <destination>.jsonsave.lock beside the final JSON.
    If the destination path was unset, this became root-level None.jsonsave.lock.
    Locks are transient coordination artifacts, so they belong in the scanner
    Temp root, not beside profiles/scan results and never in the script root.
    """
    if path is None:
        raw, reason = 'umige.json', ''
    else:
        raw, reason = core_path_text(path, field_name='json_lock_path')
    if reason:
        raise ValueError(reason)
    if raw.strip().lower() in {'', 'none', 'null'}:
        raw = 'umige.json'
    try:
        base = Path(raw).name or 'umige.json'
    except JSON_PERSISTENCE_EXCEPTIONS:
        base = 'umige.json'
    safe = ''.join((ch if ch.isalnum() or ch in '._-' else '_' for ch in base)).strip('._ ') or 'umige.json'
    try:
        digest = hashlib.sha256(str(Path(raw).resolve()).encode('utf-8', 'ignore')).hexdigest()[:16]
    except JSON_PERSISTENCE_EXCEPTIONS:
        digest = str(os.getpid())
    lock_name = str.__add__(safe, str.__add__('.', str.__add__(digest, '.jsonsave.lock')))
    return PurePath.__str__(_umige_runtime_temp_dir() / lock_name)

def _umige_acquire_json_file_lock(path: object, timeout: object=120.0, stale_after: object=300.0) -> object:
    """Small cross-process lock for JSON save/backup rotation on Windows/Sandboxie."""
    path_text, path_reason = core_path_text(path, field_name='json_lock_target')
    if path_reason:
        raise ValueError(path_reason)
    timeout_value, timeout_reason = no_hook_finite_float(
        timeout,
        default=120.0,
        minimum=0.0,
        reason='json_lock_timeout_rejected',
    )
    stale_value, stale_reason = no_hook_finite_float(
        stale_after,
        default=300.0,
        minimum=0.0,
        reason='json_lock_stale_after_rejected',
    )
    if timeout_reason:
        raise ValueError(timeout_reason)
    if stale_reason:
        raise ValueError(stale_reason)
    lock_path = _umige_json_lock_path(path_text)
    start = time.time()
    fd = None
    while True:
        try:
            Path(lock_path).parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                lock_record = ''.join((
                    'pid=',
                    int.__str__(os.getpid()),
                    ' target=',
                    str(Path(path_text).resolve()),
                    ' time=',
                    float.__str__(time.time()),
                    '\n',
                ))
                os.write(fd, lock_record.encode('utf-8', errors='ignore'))
            except JSON_PERSISTENCE_EXCEPTIONS as _umige_suppressed_exc:
                try:
                    record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
                except JSON_PERSISTENCE_EXCEPTIONS as _umige_reporting_exc:
                    _ = _umige_reporting_exc
            return (fd, lock_path)
        except FileExistsError:
            try:
                age = time.time() - os.path.getmtime(lock_path)
                if age > stale_value:
                    os.remove(lock_path)
                    continue
            except JSON_PERSISTENCE_EXCEPTIONS as _umige_suppressed_exc:
                try:
                    record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
                except JSON_PERSISTENCE_EXCEPTIONS as _umige_reporting_exc:
                    _ = _umige_reporting_exc
            if time.time() - start >= timeout_value:
                raise TimeoutError(str.__add__('timed out waiting for JSON save lock: ', lock_path))
            time.sleep(0.05)
        except JSON_PERSISTENCE_EXCEPTIONS:
            if time.time() - start >= timeout_value:
                raise
            time.sleep(0.05)

def _umige_release_json_file_lock(fd: object, lock_path: object) -> None:
    try:
        if fd is not None:
            os.close(fd)
    except JSON_PERSISTENCE_EXCEPTIONS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except JSON_PERSISTENCE_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    try:
        if lock_path:
            os.remove(lock_path)
    except JSON_PERSISTENCE_EXCEPTIONS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except JSON_PERSISTENCE_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc

def _quarantine_corrupt_json_file(path: object, reason: object=None, *, log_context: object='json_load') -> object:
    """Move a corrupt JSON file aside instead of silently overwriting it.

    This is a forensic visibility boundary: corrupted persistent JSON should not
    be treated as a benign cache miss because that creates a false-success
    recovery state and destroys the original evidence on the next write.
    Any failed quarantine attempt is recorded before the degraded ``None``
    result is returned so corrupt persistent state cannot disappear as an
    unexplained cache miss.
    """
    path_text, path_reason = core_path_text(path, field_name='corrupt_json_path')
    if path_reason:
        _jsonio_record_degraded('jsonio_corrupt_quarantine_path_rejected', ValueError(path_reason), domain='persistence')
        return None
    quarantined_path = None
    try:
        if not Path(path_text).exists():
            return None
        p = Path(path_text)
        stamp = int(time.time() * 1000000)
        quarantine_name = ''.join((p.name, '.corrupt.', int.__str__(os.getpid()), '.', int.__str__(stamp)))
        quarantine = p.with_name(quarantine_name)
        replace_failed = False
        try:
            durable_replace_regular_file(p, quarantine)
        except JSON_PERSISTENCE_EXCEPTIONS as replace_exc:
            _jsonio_record_degraded('jsonio_corrupt_quarantine_replace_failed', replace_exc, domain='persistence')
            replace_failed = True
        if replace_failed:
            return None
        try:
            log_error(''.join((
                _jsonio_safe_text(log_context, replacement='json_load'),
                ': quarantined corrupt JSON ',
                path_text,
                ' -> ',
                PurePath.__str__(quarantine),
                ': ',
                _jsonio_safe_text(reason, replacement='corrupt_json'),
            )))
        except JSON_PERSISTENCE_EXCEPTIONS as telemetry_exc:
            _jsonio_record_degraded('jsonio_telemetry_record_failed', telemetry_exc, domain='telemetry')
        quarantined_path = str(quarantine)
    except JSON_PERSISTENCE_EXCEPTIONS as quarantine_exc:
        _jsonio_record_degraded('jsonio_corrupt_quarantine_failed', quarantine_exc, domain='persistence')
    return quarantined_path

def _vt_error_payload_from_http_error(exc: object) -> object:
    try:
        raw = exc.read().decode('utf-8', 'replace')
        data = json.loads(raw) if raw else {}
        if isinstance(data, dict):
            return data
    except JSON_PERSISTENCE_EXCEPTIONS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except JSON_PERSISTENCE_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    return {}

def _write_download_meta(dest: object, meta: object, *, download_meta_path: object=_download_meta_path, atomic_json_save_func: object=None) -> object:
    """Persist YARA download metadata and report durable success truthfully."""
    dest_text, dest_reason = core_path_text(dest, field_name='download_destination')
    meta_items = no_hook_mapping_items(meta)
    if dest_reason or meta_items is None:
        reason = dest_reason or 'download_metadata_mapping_rejected'
        _jsonio_record_degraded('yara_download_meta_write_rejected', ValueError(reason), domain='yara')
        return False
    try:
        meta_path = download_meta_path(dest_text)
        meta_value = dict(meta_items)
        meta_value.setdefault('updated', time.time())
        writer = atomic_json_save if atomic_json_save_func is None else atomic_json_save_func
        ok = writer(meta_path, meta_value, backups=1) is True
    except JSON_PERSISTENCE_EXCEPTIONS as e:
        _jsonio_record_degraded('yara_download_meta_write_failed', e, domain='yara')
        log_error(_jsonio_exception_text('YARA download metadata save skipped: ', e))
        ok = False
    return ok is True

def atomic_json_save(path: object, obj: object, backups: object=2, lock: object=None) -> object:
    """
    Cross-process-safe atomic JSON save.

    Parent writes only for shared persistent JSONs during process scans.
    Uses a unique temp file per writer plus a per-destination cross-process
    lock around backup rotation and final replace.
    """
    path_text, path_reason = core_path_text(path, field_name='atomic_json_destination')
    if path_reason or path_text.strip().lower() in {'', 'none', 'null'}:
        raise ValueError('atomic_json_save requires an explicit destination path; refusing root-level None artifacts')
    backup_count, backup_reason = no_hook_exact_nonnegative_int(backups, default=2)
    if backup_reason:
        raise ValueError(backup_reason)
    path_candidate = Path(path_text).absolute()
    if path_contains_filesystem_alias(path_candidate.parent):
        raise ValueError('atomic_json_save_destination_alias_rejected')
    path = str(path_candidate)
    directory = str(Path(path).parent) or '.'
    Path(directory).mkdir(parents=True, exist_ok=True)
    tmp = _umige_unique_json_tmp_path(path)
    if lock is not None and type(lock) is not _RLOCK_TYPE:
        raise ValueError('atomic_json_save_lock_rejected')
    save_lock = JSON_SAVE_LOCK if lock is None else lock
    fd = None
    lock_path = None
    with save_lock:
        try:
            safe_obj = make_json_safe(obj)
            validate_persistent_record_semantics(safe_obj, context='atomic_json_save_expected')
            with Path(tmp).open('w', encoding='utf-8') as f:
                json.dump(safe_obj, f, indent=2, sort_keys=True, allow_nan=False)
                f.flush()
                flush_open_writable_file(f.fileno())
            verify_persistent_json_file(tmp, expected=safe_obj, context='atomic_json_save_tmp', require_match=True)
            fd, lock_path = _umige_acquire_json_file_lock(path)
            if Path(path).exists() and backup_count:
                for i in range(backup_count, 0, -1):
                    src = str.__add__(path, str.__add__('.bak', int.__str__(i)))
                    dst = str.__add__(path, str.__add__('.bak', int.__str__(i + 1)))
                    if Path(src).exists():
                        if i == backup_count:
                            try:
                                os.remove(src)
                                flush_directory(Path(src).parent)
                            except FileNotFoundError:
                                continue
                        else:
                            try:
                                durable_replace_regular_file(Path(src), Path(dst))
                            except FileNotFoundError:
                                continue
                backup_path = Path(str.__add__(path, '.bak1'))
                backup_tmp = Path(_umige_unique_json_tmp_path(str(backup_path)))
                try:
                    shutil.copy2(path, backup_tmp)
                    durable_replace_regular_file(backup_tmp, backup_path)
                finally:
                    backup_tmp.unlink(missing_ok=True)
            durable_replace_regular_file(Path(tmp), Path(path))
            if Path(path).stat().st_size <= ATOMIC_JSON_VERIFY_MAX_BYTES:
                verify_persistent_json_file(path, expected=safe_obj, context='atomic_json_save_final', require_match=True)
            elif Path(path).stat().st_size <= 0:
                raise ValueError(str.__add__('atomic save produced empty JSON file: ', path))
            else:
                validate_persistent_record_semantics(safe_obj, context='atomic_json_save_large_expected')
            return True
        except JSON_PERSISTENCE_EXCEPTIONS:
            try:
                if Path(tmp).exists():
                    os.remove(tmp)
            except JSON_PERSISTENCE_EXCEPTIONS as cleanup_error:
                log_error(_jsonio_exception_text(str.__add__('atomic_json_save cleanup failed for ', str.__add__(path, ': ')), cleanup_error))
            raise
        finally:
            _umige_release_json_file_lock(fd, lock_path)

def make_json_safe(value: object, _key: object=None) -> object:
    """Convert runtime objects into compact JSON-safe values without caller hooks.

    Long decoded buffers/strings are summarized so large malicious sample runs
    finalize deterministically.  Unknown objects are rejected with explicit
    evidence instead of being stringified, iterated, or materialized through
    caller-owned protocols.
    """
    key_text = _jsonio_safe_text(_key, replacement='') if _key is not None else ''
    bulky_keys = {'strings_blob', 'string_blob', 'raw_strings', 'decoded_text', 'text', 'raw_sample', 'content', 'blob', 'decompiled_source', 'ilspy_output'}
    mapping_items = no_hook_mapping_items(value)
    if mapping_items is not None:
        out = {}
        for index, (key, item) in enumerate(mapping_items):
            replacement_key = _jsonio_index_text('jsonio_key_', index)
            key_s = _jsonio_safe_text(key, replacement=replacement_key) or replacement_key
            if key_s in out:
                key_s = ''.join((key_s, '#', int.__str__(index)))
            if key_s.lower() in bulky_keys and type(item) is str:
                if len(item) > 2048:
                    out[key_s] = {'truncated': True, 'chars': len(item), 'sample': item[:2048]}
                else:
                    out[key_s] = str.__str__(item)
            else:
                out[key_s] = make_json_safe(item, key_s)
        return out
    if type(value) in (list, tuple):
        limit = 64 if key_text.lower() in {'decoded_payloads', 'decode_records', 'evidence_links'} else None
        seq = value[:limit] if limit else value
        out = [make_json_safe(item, key_text) for item in seq]
        if limit and len(value) > limit:
            out.append({'truncated': True, 'items': len(value) - limit})
        return out
    if type(value) in (set, frozenset):
        safe_items = [make_json_safe(item, key_text) for item in value]
        return sorted(safe_items, key=_json_safe_order_key)
    path_text = _jsonio_stdlib_path_text(value)
    if path_text is not None:
        return path_text
    if type(value) is str and len(value) > 8192:
        return {'truncated': True, 'chars': len(value), 'sample': value[:4096]}
    if type(value) is str:
        return str.__str__(value)
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is float:
        try:
            if math.isfinite(value):
                return value
        except JSON_PERSISTENCE_EXCEPTIONS as telemetry_exc:
            _jsonio_record_degraded('jsonio_telemetry_record_failed', telemetry_exc, domain='telemetry')
        return {'non_finite_float': float.__str__(value)}
    return _jsonio_unsupported_value(value, field_name=key_text or 'jsonio_value')
