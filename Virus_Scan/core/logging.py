from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.contracts.env_config import bool_env, int_env, str_env, float_env
from Virus_Scan.runtime.runtime_flags import runtime_flag_claim_once
from Virus_Scan.scheduler.api.runtime import prepare_raw_retry_job
from Virus_Scan.utils.probability import safe_clamp
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
from Virus_Scan.runtime.api import (
    flush_open_writable_file,
)
from Virus_Scan.runtime.detector_state import detector_errors_snapshot, record_detector_failure, detector_state_is_strict
import json
import logging
import math
import os
import struct
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path
from Virus_Scan.runtime.config_state import get_deep_scan_mode
from Virus_Scan.runtime.config_values import runtime_value
from Virus_Scan.runtime.resource_paths import yara_dir
from Virus_Scan.yara.constants import YARA_CACHE_DIRNAME
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_failure,
    no_hook_finite_float,
    no_hook_exact_owner_field,
    no_hook_json_sort_key,
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_sequence_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.core.path_utils import core_path_text
from Virus_Scan.utils.tagging import normalize_tags

PLR2004N256 = 256
PLR2004N25_0 = 25.0
PLR2004N267 = 267
PLR2004N4 = 4
PLR2004N429 = 429
PLR2004N50_0 = 50.0
PLR2004N512 = 512
PLR2004N523 = 523
PLR2004N6 = 6
PLR2004N64 = 64
PLR2004N75_0 = 75.0
PLR2004N8192 = 8192

_SAFE_OS_ERROR_TYPES = (OSError, PermissionError, FileExistsError, FileNotFoundError)
YARA_DOWNLOAD_ERROR_LOCK = threading.Lock()
DECODE_LAYER_DEBUG = bool_env("UMIGE_DECODE_LAYER_DEBUG", default=False)


def _yara_cache_dir() -> str:
    cache_dir = Path(str(yara_dir())) / YARA_CACHE_DIRNAME
    cache_dir.mkdir(parents=True, exist_ok=True)
    return str(cache_dir)


def _simple_network_available(timeout: float = 5) -> bool:
    for url in ("https://github.com/", "https://example.com/"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "UMIGE-network-check"})
            with urllib.request.urlopen(req, timeout=timeout):
                return True
        except TELEMETRY_FAILURE_ERRORS:
            continue
    return False


def _queue_fs_backoff(index: object, delay: object = None) -> float:
    raw_base = delay if delay is not None else float_env("UMIGE_QUEUE_FS_RETRY_DELAY", 0.025, 0.0, None)
    base, base_reason = no_hook_finite_float(raw_base, default=0.025, reason="queue_fs_retry_delay_rejected")
    clean_index, index_reason = no_hook_exact_nonnegative_int(index, default=0, reason="queue_fs_retry_index_rejected")
    if base_reason or index_reason:
        return 0.025
    return min(0.5, base * (1.0 + clean_index))


def _umige_rva_to_offset(rva: int, sections: object) -> int | None:
    try:
        for sec in no_hook_sequence_items(sections):
            sec_items = no_hook_mapping_items(sec)
            if sec_items is None:
                continue
            section = dict(sec_items)
            start = int(section.get("virtual_address", 0))
            end = start + max(int(section.get("virtual_size", 0)), int(section.get("raw_size", 0)), 1)
            if start <= rva < end:
                return int(section.get("raw_ptr", 0)) + (rva - start)
    except TELEMETRY_FAILURE_ERRORS:
        return -1
    return None


def _umige_u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0] if off + 2 <= len(data) else 0


def _umige_u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0] if off + 4 <= len(data) else 0


def _umige_u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0] if off + 8 <= len(data) else 0


def _umige_cstr(data: bytes, off: int | None, limit: int = 260) -> str:
    if off is None or off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, min(len(data), off + limit))
    if end < 0:
        end = min(len(data), off + limit)
    return data[off:end].decode("latin1", errors="ignore")






def _global_raw_publish_job(queue_dir: object, job: object) -> bool:
    del job, queue_dir  # Explicitly unused contract parameters.
    raise RuntimeError("global_raw_publish_job_dependency_unavailable")


def _core_exception_text(prefix: object, exc: object) -> object:
    return str.__add__(prefix, no_hook_type_name(exc))


def _core_run_id() -> str:
    return str.__add__(int.__str__(time.time_ns() // 1_000_000), str.__add__("_", int.__str__(os.getpid())))


def _core_text(value: object, *, replacement: str) -> str:
    text, reason = no_hook_text(value, unsupported_reason='core_logging_text_rejected')
    if reason or text == '':
        return replacement
    return text


def _safe_os_error_int(exc: object, name: object) -> object:
    if type(exc) not in _SAFE_OS_ERROR_TYPES:
        return None
    try:
        value = BaseException.__getattribute__(exc, name)
    except TELEMETRY_FAILURE_ERRORS as attr_exc:
        try:
            record_suppressed_failure('os_error_int_attribute_unavailable', attr_exc, domain='scheduler')
        except TELEMETRY_FAILURE_ERRORS as telemetry_exc:
            _ = telemetry_exc
        return None
    return value if type(value) is int else None


def _queue_fs_busy_message(prefix: object, *, log_context: object, path_fields: object, exc: object) -> object:
    context_text = _core_text(log_context, replacement='queue_fs')
    parts = [prefix, ' context=', context_text]
    for label, value in path_fields:
        parts.extend((' ', label, '=', value))
    parts.extend((': ', no_hook_type_name(exc)))
    return ''.join(parts)


def read_file_bytes(path: object, max_size: object=5_000_000) -> object:
    path_text, path_reason = core_path_text(path, field_name='core_read_path')
    if path_reason:
        raise ValueError(path_reason)
    p = Path(path_text)
    with p.open("rb") as fh:
        if max_size is None:
            return fh.read()
        size, size_reason = no_hook_exact_nonnegative_int(max_size, default=0)
        if size_reason:
            if type(max_size) is int and max_size < 0:
                return fh.read()
            raise ValueError(size_reason)
        return fh.read(size)

def deep_scan_thorough_enabled() -> object:
    mode, reason = no_hook_text(
        get_deep_scan_mode("auto"),
        missing_reason='deep_scan_mode_missing',
        unsupported_reason='deep_scan_mode_rejected',
    )
    return False if reason else mode.lower() in {"thorough", "deep", "exhaustive"}

def _umige_retry_max(kind: object) -> object:
    kind_text, reason = no_hook_text(kind, unsupported_reason='retry_kind_rejected')
    env_name = 'UMIGE_RAW_RETRY_MAX' if not reason and kind_text == 'raw' else 'UMIGE_FILE_RETRY_MAX'
    return int_env(env_name, 1, 0, None)

def _calibrated_sigmoid_probability(logit_value: object, temperature: object=1.0) -> object:
    """Numerically stable calibrated sigmoid for log-odds fusion output."""
    logit, logit_reason = no_hook_finite_float(logit_value, reason='calibrated_logit_rejected')
    temp, temp_reason = no_hook_finite_float(temperature, default=1.0, reason='calibrated_temperature_rejected')
    if logit_reason or temp_reason or temp == 0.0:
        raise ValueError(logit_reason or temp_reason or 'calibrated_temperature_zero')
    x = logit / max(1e-06, temp)
    if x >= 0:
        z = math.exp(-x)
        return safe_clamp(1.0 / (1.0 + z))
    z = math.exp(x)
    return safe_clamp(z / (1.0 + z))

def _decode_debug(msg: object) -> None:
    """Quiet debug hook for expected decode misses; never logs as ERROR."""
    try:
        if DECODE_LAYER_DEBUG:
            text, reason = no_hook_text(msg, unsupported_reason='decode_debug_text_rejected')
            logging.debug(text if not reason else 'decode_debug_text_rejected')
    except TELEMETRY_FAILURE_ERRORS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except TELEMETRY_FAILURE_ERRORS as _umige_reporting_exc:
            _ = _umige_reporting_exc

def _find_known_eof_offset(data: object) -> object:
    """Return offset just after a valid container EOF marker when available."""
    try:
        if not data:
            return (None, None)
        if data.startswith(b'\x89PNG\r\n\x1a\n'):
            idx = data.rfind(b'IEND')
            if idx >= PLR2004N4:
                end = idx + 8
                return (min(end, len(data)), 'png_eof')
        if data.startswith(b'\xff\xd8'):
            idx = data.rfind(b'\xff\xd9')
            if idx >= 0:
                return (idx + 2, 'jpeg_eof')
        if data.startswith((b'GIF87a', b'GIF89a')):
            idx = data.rfind(b';')
            if idx >= 0:
                return (idx + 1, 'gif_eof')
        if data.startswith(b'BM') and len(data) >= PLR2004N6:
            declared = struct.unpack_from('<I', data, 2)[0]
            if 0 < declared <= len(data):
                return (declared, 'bmp_declared_eof')
        if data.startswith(b'MZ') and len(data) > PLR2004N256:
            pe_off = struct.unpack_from('<I', data, 60)[0]
            if 0 <= pe_off + 24 < len(data) and data[pe_off:pe_off + 4] == b'PE\x00\x00':
                num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
                opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
                sec_off = pe_off + 24 + opt_size
                max_end = 0
                for i in range(min(num_sections, 96)):
                    off = sec_off + i * 40
                    if off + 40 > len(data):
                        break
                    raw_size = struct.unpack_from('<I', data, off + 16)[0]
                    raw_ptr = struct.unpack_from('<I', data, off + 20)[0]
                    if raw_ptr > 0 and raw_size > 0:
                        max_end = max(max_end, raw_ptr + raw_size)
                if 0 < max_end <= len(data):
                    return (max_end, 'pe_section_eof')
    except TELEMETRY_FAILURE_ERRORS as e:
        log_error(_core_exception_text('EOF offset detection failed: ', e))
    return (None, None)

def _log_yara_download_failure_once(url: object=None) -> None:
    """Emit only one YARA auto-download failure per CLI run, even under multiprocessing."""
    del url  # Explicitly unused contract parameters.
    with YARA_DOWNLOAD_ERROR_LOCK:
        if not runtime_flag_claim_once('yara_download_error_logged'):
            return
    marker_already_logged = False
    try:
        run_id = str_env('UMIGE_RUN_ID', _core_run_id())
        marker = str(Path(_yara_cache_dir()) / str.__add__('.yara_download_error_logged_', run_id))
        fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
    except FileExistsError:
        marker_already_logged = True
    except TELEMETRY_FAILURE_ERRORS as exc:
        record_suppressed_failure('logging_directory_prepare_failed', exc, domain='logging')
    if marker_already_logged:
        return
    if not _simple_network_available():
        log_error('No Internet Cannot Download Updated Rules')
    else:
        log_error('Cannot Download Updated Rules; check YARA Forge download link')

def queue_safe_unlink(path: object, *, retries: object=None, delay: object=None, log_context: object=None) -> object:
    if retries is None:
        retries = int_env('UMIGE_QUEUE_FS_RETRIES', 12, 1, None)
    retry_count, retry_reason = no_hook_exact_nonnegative_int(retries, default=1)
    if retry_reason:
        return False
    retries = max(1, retry_count)
    p_s, path_reason = core_path_text(path, field_name='queue_unlink_path')
    if path_reason:
        record_suppressed_failure(
            'queue_safe_unlink_path_rejected',
            ValueError(path_reason),
            domain='scheduler',
        )
        return False
    last_exc = None
    unlinked = False
    already_missing = False
    terminal_failure = False
    for i in range(retries):
        try:
            Path(p_s).unlink()
            unlinked = True
            break
        except FileNotFoundError as e:
            last_exc = e
            already_missing = True
            break
        except PermissionError as e:
            last_exc = e
            time.sleep(_queue_fs_backoff(i, delay))
        except OSError as e:
            last_exc = e
            winerr = _safe_os_error_int(e, 'winerror')
            if winerr in (5, 32, 33) or _safe_os_error_int(e, 'errno') in (13, 16, 26):
                time.sleep(_queue_fs_backoff(i, delay))
                continue
            terminal_failure = True
            break
        except TELEMETRY_FAILURE_ERRORS as e:
            last_exc = e
            terminal_failure = True
            break
    if unlinked or already_missing:
        return True
    try:
        if log_context and (last_exc is not None or terminal_failure):
            log_error(_queue_fs_busy_message('queue fs unlink busy after retries', log_context=log_context, path_fields=(('path', p_s),), exc=last_exc))
    except TELEMETRY_FAILURE_ERRORS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except TELEMETRY_FAILURE_ERRORS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    return False

def _safe_logit_probability(p: object) -> object:
    """Convert a bounded 0..1 probability-like signal into log odds."""
    value, reason = no_hook_finite_float(p, reason='logit_probability_rejected')
    if reason:
        raise ValueError(reason)
    p = safe_clamp(value, 1e-05, 1.0 - 1e-05)
    try:
        return math.log(p / (1.0 - p))
    except TELEMETRY_FAILURE_ERRORS as e:
        log_error(_core_exception_text('safe logit failed: ', e))
        raise ValueError('logit_probability_failed') from e

def _safe_stage_collect(stage_name: object, fn: object, *args: object, **kwargs: object) -> object:
    """Run one evidence collector and return a uniform dict without raising."""
    stage_text, stage_reason = no_hook_text(stage_name, unsupported_reason='stage_name_rejected')
    if stage_reason or stage_text == '':
        stage_text = 'stage_input_rejected'
    out = {'name': stage_text, 'tags': [], 'meta': {}, 'suspicious': False, 'error': None}
    try:
        value = fn(*args, **kwargs)
        if type(value) is tuple:
            first = value[0] if len(value) > 0 else []
            second = value[1] if len(value) > 1 else None
            out['tags'] = normalize_tags(first)
            second_items = no_hook_mapping_items(second)
            if second_items is not None:
                second_values = dict(second_items)
                out['meta'] = no_hook_materialize(second_values, reason_prefix='stage_collect_meta')
                if dict.get(second_values, 'suspicious') is True:
                    out['suspicious'] = True
            elif type(second) is bool:
                out['suspicious'] = second
            elif type(second) in (int, float):
                score, score_reason = no_hook_finite_float(second, reason='stage_score_rejected')
                out['meta'] = {'score': score} if not score_reason else no_hook_failure(score_reason, second)
            elif second is not None:
                out['meta'] = no_hook_failure('stage_metadata_rejected', second)
        else:
            out['tags'] = normalize_tags(value)
    except TELEMETRY_FAILURE_ERRORS as e:
        out['error'] = no_hook_type_name(e)
        try:
            record_detector_error(stage_text, e, context={'stage_parallel': True})
        except TELEMETRY_FAILURE_ERRORS:
            log_error('stage-parallel collector failed')
    return out

def _sample_file_prefix_suffix(path: object, prefix_size: object=None, suffix_size: object=None) -> object:
    path_text, path_reason = core_path_text(path, field_name='sample_path')
    if path_reason:
        record_detector_error(
            '_sample_file_prefix_suffix',
            ValueError(path_reason),
            context={'path_evidence': no_hook_failure(path_reason, path)},
        )
        return (b'', b'', 0)
    try:
        if prefix_size is None:
            prefix_size = 32768
            if deep_scan_thorough_enabled():
                prefix_size = max(prefix_size, 1048576)
        if suffix_size is None:
            suffix_size = 32768
            if deep_scan_thorough_enabled():
                suffix_size = max(suffix_size, 1048576)
        prefix_size, prefix_reason = no_hook_exact_nonnegative_int(prefix_size, default=32768)
        suffix_size, suffix_reason = no_hook_exact_nonnegative_int(suffix_size, default=32768)
        if prefix_reason or suffix_reason:
            raise ValueError(prefix_reason or suffix_reason)
        size = Path(path_text).stat().st_size
        with Path(path_text).open('rb') as f:
            prefix = f.read(min(prefix_size, size))
            if size > prefix_size:
                f.seek(max(0, size - suffix_size))
                suffix = f.read(min(suffix_size, size))
            else:
                suffix = b''
        return (prefix, suffix, size)
    except TELEMETRY_FAILURE_ERRORS as e:
        record_detector_error('_sample_file_prefix_suffix', e, context={'file': path_text})
        return (b'', b'', 0)

def _scan_png_chunks(data: object, tags: object) -> object:
    """Conservative PNG ancillary/chunk anomaly checks."""
    suspicious = False
    try:
        if not data.startswith(b'\x89PNG\r\n\x1a\n'):
            return False
        pos = 8
        seen_iend = False
        unusual_private = 0
        text_payload = b''
        while pos + 12 <= len(data):
            length = int.from_bytes(data[pos:pos + 4], 'big')
            ctype = data[pos + 4:pos + 8]
            if length < 0 or length > 64 * 1024 * 1024:
                tags += ['png_invalid_chunk_length', 'stego_statistical_anomaly']
                return True
            chunk_start = pos + 8
            chunk_end = chunk_start + length
            crc_end = chunk_end + 4
            if crc_end > len(data):
                tags += ['png_truncated_or_malformed_chunk', 'stego_statistical_anomaly']
                return True
            name = ctype.decode('latin1', errors='ignore')
            if len(name) == PLR2004N4 and name[1:2].islower():
                unusual_private += 1
            if ctype in {b'tEXt', b'zTXt', b'iTXt'}:
                text_payload += data[chunk_start:min(chunk_end, chunk_start + 8192)]
                if length >= PLR2004N8192:
                    tags += ['large_png_text_chunk', 'stego_statistical_anomaly']
                    suspicious = True
            if ctype == b'IEND':
                seen_iend = True
                break
            pos = crc_end
        if unusual_private >= 2:
            tags += ['png_private_chunks', 'stego_statistical_anomaly']
            suspicious = True
        low = text_payload.lower()
        if any((x in low for x in [b'powershell', b'cmd.exe', b'http://', b'https://', b'base64', b'frombase64string'])):
            tags += ['suspicious_png_text_payload', 'embedded_command_or_url']
            suspicious = True
        if not seen_iend:
            tags += ['png_missing_iend', 'stego_statistical_anomaly']
            suspicious = True
    except TELEMETRY_FAILURE_ERRORS as e:
        log_error(_core_exception_text('PNG chunk stego scan failed: ', e))
    return suspicious

def _sigmoid_100(raw_value: object, midpoint: object=50.0, scale: object=12.0) -> object:
    """Numerically stable sigmoid mapped to 0..100."""
    value, value_reason = no_hook_finite_float(raw_value, reason='sigmoid_score_rejected')
    midpoint_value, midpoint_reason = no_hook_finite_float(midpoint, default=50.0, reason='sigmoid_midpoint_rejected')
    scale_value, scale_reason = no_hook_finite_float(scale, default=12.0, reason='sigmoid_scale_rejected')
    if value_reason or midpoint_reason or scale_reason or scale_value == 0.0:
        raise ValueError(value_reason or midpoint_reason or scale_reason or 'sigmoid_scale_zero')
    x = (value - midpoint_value) / max(1e-06, scale_value)
    if x >= 0:
        z = math.exp(-x)
        p = 1.0 / (1.0 + z)
    else:
        z = math.exp(x)
        p = z / (1.0 + z)
    return safe_clamp(p * 100.0, 0.0, 100.0)

def _stage_read_bytes(path: object, max_size: object=2000000) -> object:
    """Small top-level read helper for process-backed micro collectors."""
    try:
        return read_file_bytes(path, max_size=max_size)
    except TELEMETRY_FAILURE_ERRORS as e:
        try:
            record_detector_error(
                '_stage_read_bytes',
                e,
                context={'path_evidence': no_hook_failure('stage_read_path_unavailable', path)},
            )
        except TELEMETRY_FAILURE_ERRORS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except TELEMETRY_FAILURE_ERRORS as _umige_reporting_exc:
                _ = _umige_reporting_exc
        return b''

def _umige_parse_pe_import_names(data: object, sections: object, *, is_64: object=False) -> object:
    imports = []
    try:
        pe_off = _umige_u32(data, 60)
        opt_off = pe_off + 24
        magic = _umige_u16(data, opt_off)
        is_64 = magic == PLR2004N523
        dd_off = opt_off + (112 if is_64 else 96)
        import_rva = _umige_u32(data, dd_off + 8)
        off = _umige_rva_to_offset(import_rva, sections)
        if off is None:
            return imports
        step = 8 if is_64 else 4
        ordinal_mask = 9223372036854775808 if is_64 else 2147483648
        while off + 20 <= len(data) and len(imports) < PLR2004N512:
            original_first_thunk = _umige_u32(data, off)
            name_rva = _umige_u32(data, off + 12)
            first_thunk = _umige_u32(data, off + 16)
            if original_first_thunk == 0 and name_rva == 0 and (first_thunk == 0):
                break
            dll = _umige_cstr(data, _umige_rva_to_offset(name_rva, sections)).lower()
            thunk_off = _umige_rva_to_offset(original_first_thunk or first_thunk, sections)
            funcs = []
            while thunk_off is not None and thunk_off + step <= len(data) and (len(funcs) < PLR2004N512):
                thunk = _umige_u64(data, thunk_off) if is_64 else _umige_u32(data, thunk_off)
                if thunk == 0:
                    break
                if thunk & ordinal_mask:
                    funcs.append('ordinal_import')
                else:
                    name_off = _umige_rva_to_offset(int(thunk), sections)
                    name = _umige_cstr(data, name_off + 2 if name_off is not None else None)
                    if name:
                        funcs.append(name)
                thunk_off += step
            imports.append((dll, funcs))
            off += 20
    except TELEMETRY_FAILURE_ERRORS as e:
        log_error(_core_exception_text('pure PE import parse failed: ', e))
    return imports

def _umige_prepare_raw_retry(queue_dir: object, job: object, result: object) -> object:
    published = False
    try:
        retry_job = prepare_raw_retry_job(job, result, max_retries_default=_umige_retry_max('raw'))
        if retry_job is not None:
            published = bool(_global_raw_publish_job(queue_dir, retry_job))
    except TELEMETRY_FAILURE_ERRORS as e:
        try:
            log_error(_core_exception_text('raw retry publish failed: ', e))
        except TELEMETRY_FAILURE_ERRORS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except TELEMETRY_FAILURE_ERRORS as _umige_reporting_exc:
                _ = _umige_reporting_exc
    return published



def _cache_key_part(value: object) -> object:
    text, reason = no_hook_text(value, unsupported_reason='cache_key_part_rejected')
    if not reason:
        return text
    items = no_hook_mapping_items(value)
    if items is not None:
        normalized = []
        for index, (key, item) in enumerate(items):
            key_text, key_reason = no_hook_text(key, unsupported_reason='cache_key_mapping_key_rejected')
            item_text, item_reason = no_hook_text(item, unsupported_reason='cache_key_mapping_value_rejected')
            normalized.append((
                key_text if not key_reason else ''.join(('key_rejected_', int.__str__(index), ':', no_hook_type_name(key))),
                item_text if not item_reason else str.__add__('value_rejected:', no_hook_type_name(item)),
            ))
        return tuple(sorted(normalized))
    values = no_hook_sequence_items(value)
    if values:
        return tuple(sorted((_cache_key_part(item) for item in values), key=no_hook_json_sort_key))
    return str.__add__('cache_key_part_rejected:', no_hook_type_name(value))


def cache_key(namespace: object, *parts: object) -> object:
    """
    Stable cache-key builder.

    Fixes:
    - old code used cache_key as both dict and function
    - makes tuple-safe keys for graph/evasion/risk caches
    """
    namespace_text, namespace_reason = no_hook_text(
        namespace,
        unsupported_reason='cache_namespace_rejected',
    )
    if namespace_reason:
        namespace_text = str.__add__('cache_namespace_rejected:', no_hook_type_name(namespace))
    return (namespace_text, tuple(_cache_key_part(part) for part in parts))

def call_detector(detector_fn: object, *args: object, context: object=None, **kwargs: object) -> object:
    """Run a detector through the canonical failure contract.

    Detector failures are reported and propagated.  The previous synthetic-return
    API hid failed detectors behind synthetic scores, which created a duplicate
    execution path and made scanner evidence nondeterministic.
    """
    result = detector_fn(*args, **kwargs)
    if result is None:
        exc = ValueError('detector returned None')
        name = no_hook_type_name(detector_fn)
        record_detector_error(name, exc, context=context)
        raise exc
    return result

def classify(score: object) -> object:
    """Canonical 0-100 verdict model used by all scoring paths."""
    score, reason = no_hook_finite_float(
        score,
        reason='classification_score_rejected',
        non_finite_reason='classification_score_non_finite',
    )
    if reason:
        raise ValueError(reason)
    if score >= PLR2004N75_0:
        return ('malicious', 0.95)
    if score >= PLR2004N50_0:
        return ('high_confidence', 0.8)
    if score >= PLR2004N25_0:
        return ('low_confidence', 0.55)
    return ('benign_clean', 0.2)

def configure_single_parent_log(log_path: object=None) -> object:
    """Attach one parent-owned text log for the current scan.

    The CLI supplies the current Scan Logs generation scanlog, preserving the established
    wipe-on-new-scan behavior through FileHandler(mode="w").  Passing None keeps
    console-only logging, which is used by the explicit --no-scanlog escape hatch
    and by worker shards.
    """
    if log_path is None:
        return None
    path_text, path_reason = core_path_text(log_path, field_name='scan_log_path')
    if path_reason:
        record_suppressed_failure(
            'scan_log_path_rejected',
            ValueError(path_reason),
            domain='logging',
        )
        return None
    try:
        if bool_env('UMIGE_PROCESS_SHARD', default=False):
            return None
        path = str(Path(path_text).resolve())
        parent = Path(path).parent
        if str(parent):
            parent.mkdir(parents=True, exist_ok=True)
        root = logging.getLogger()
        for h in root.handlers:
            if type(h) is logging.FileHandler:
                base_filename = no_hook_exact_owner_field(h, logging.FileHandler, 'baseFilename')
                base_text, base_reason = core_path_text(base_filename, field_name='existing_scan_log_path')
                if not base_reason and str(Path(base_text).resolve()) == path:
                    return path
        fh = logging.FileHandler(path, mode='w', encoding='utf-8')
        fh.setLevel(logging.DEBUG if root.level <= logging.DEBUG else logging.INFO)
        fh.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        root.addHandler(fh)
        return path
    except TELEMETRY_FAILURE_ERRORS as e:
        logging.error(_core_exception_text('explicit log setup failed: ', e))
    return None

def _validate_parent_scan_log_payload(value: object, *, depth: int = 0, max_depth: int = 24, max_items: int = 20_000) -> None:
    """Reject values outside the exact JSON event contract without invoking hooks."""
    if depth > max_depth:
        raise ValueError("scan_log_event_payload_depth_limit_exceeded")
    value_type = type(value)
    if value is None or value_type is bool or value_type is int or value_type is str:
        return
    if value_type is float:
        if not math.isfinite(value):
            raise ValueError("scan_log_event_payload_non_finite_number")
        return
    if value_type is dict:
        if len(value) > max_items:
            raise ValueError("scan_log_event_payload_mapping_size_limit_exceeded")
        for key, item in dict.items(value):
            if type(key) is not str:
                raise TypeError("scan_log_event_payload_key_invalid")
            _validate_parent_scan_log_payload(item, depth=depth + 1, max_depth=max_depth, max_items=max_items)
        return
    if value_type is list or value_type is tuple:
        if len(value) > max_items:
            raise ValueError("scan_log_event_payload_sequence_size_limit_exceeded")
        for item in value:
            _validate_parent_scan_log_payload(item, depth=depth + 1, max_depth=max_depth, max_items=max_items)
        return
    raise TypeError("scan_log_event_payload_value_invalid")


def emit_parent_scan_log_line(line: object, *, mirror_console: object = True) -> str:
    """Deliver one already-materialized line through the parent logging owner.

    Parent scanlog durability must not depend on the ambient root logger level.
    The canonical file handler is therefore addressed directly, while optional
    console/capture handlers receive the same ``LogRecord`` projection.
    """
    if type(line) is not str:
        raise TypeError("scan_log_line_invalid")
    if type(mirror_console) is not bool:
        raise TypeError("scan_log_line_console_policy_invalid")
    if line == "" or len(line) > 1_000_000 or "\n" in line or "\r" in line:
        raise ValueError("scan_log_line_invalid")
    root = logging.getLogger()
    record = root.makeRecord(root.name, logging.INFO, __file__, 0, line, (), None)
    for handler in tuple(root.handlers):
        is_parent_file = type(handler) is logging.FileHandler
        if not is_parent_file and not mirror_console:
            continue
        if record.levelno < handler.level:
            continue
        handler.handle(record)
    return line


def emit_parent_scan_log_event(event_type: object, payload: object, *, mirror_console: object = True) -> str:
    """Emit one typed scan event through the canonical parent logging owner.

    FileHandler delivery is unconditional when the parent scanlog is active.
    Console mirroring is an explicit projection of the same LogRecord; subsystem
    code never writes the scanlog or prints independently.
    """
    event_text, event_reason = no_hook_text(
        event_type,
        unsupported_reason="scan_log_event_type_rejected",
    )
    if event_reason or event_text == "" or not event_text.isascii() or not event_text.replace("_", "").isalnum():
        raise ValueError("scan_log_event_type_invalid")
    if type(mirror_console) is not bool:
        raise TypeError("scan_log_event_console_policy_invalid")
    _validate_parent_scan_log_payload(payload)
    materialized = no_hook_materialize(
        payload,
        max_depth=24,
        max_items=20_000,
        reason_prefix="scan_log_event",
    )
    line = "[" + event_text.upper() + "] " + json.dumps(
        materialized,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return emit_parent_scan_log_line(line, mirror_console=mirror_console)


def release_single_parent_log(log_path: object=None) -> bool:
    """Flush, fsync, close, and detach the exact parent-owned scan log."""
    if log_path is None:
        return True
    path_text, path_reason = core_path_text(log_path, field_name='scan_log_path')
    if path_reason:
        raise ValueError(path_reason)
    target = str(Path(path_text).resolve())
    root = logging.getLogger()
    released = False
    for handler in tuple(root.handlers):
        if type(handler) is not logging.FileHandler:
            continue
        base_filename = no_hook_exact_owner_field(handler, logging.FileHandler, 'baseFilename')
        base_text, base_reason = core_path_text(base_filename, field_name='existing_scan_log_path')
        if base_reason or str(Path(base_text).resolve()) != target:
            continue
        handler.flush()
        stream = no_hook_exact_owner_field(handler, logging.FileHandler, 'stream')
        if stream is not None:
            flush_open_writable_file(stream.fileno())
        root.removeHandler(handler)
        handler.close()
        released = True
    return released

def cosine_similarity(v1: object, v2: object, node: object=None) -> object:
    del node  # Explicitly unused contract parameters.
    if type(v1) not in (tuple, list) or type(v2) not in (tuple, list):
        raise ValueError('cosine_vector_rejected')
    if len(v1) == 0 or len(v2) == 0:
        return 0.0
    try:
        left = []
        right = []
        for item in v1:
            metric, reason = no_hook_finite_float(item, reason='cosine_value_rejected')
            if reason:
                raise ValueError(reason)
            left.append(metric)
        for item in v2:
            metric, reason = no_hook_finite_float(item, reason='cosine_value_rejected')
            if reason:
                raise ValueError(reason)
            right.append(metric)
        dot = sum((a * b for a, b in zip(left, right, strict=False)))
        n1 = math.sqrt(sum((a * a for a in left))) + 1e-06
        n2 = math.sqrt(sum((b * b for b in right))) + 1e-06
        base = dot / (n1 * n2)
        return max(0.0, min(1.0, base))
    except TELEMETRY_FAILURE_ERRORS as e:
        log_error(_core_exception_text('cosine failed: ', e))
        raise ValueError('cosine_similarity_failed') from e

def get_detector_errors(*, clear: object=False) -> object:
    """Return detector errors captured during the current run."""
    if type(clear) is not bool:
        raise ValueError('detector_error_clear_rejected')
    return [dict(item) for item in detector_errors_snapshot(clear=clear)]

def has_any_tag(tags: object, *needles: object) -> object:
    """Return True when any requested tag is present, preserving concrete tag checks."""
    tagset = frozenset(normalize_tags(tags))
    needle_values = normalize_tags(needles)
    return any(needle in tagset for needle in needle_values)

def is_dotnet_pe(data: bytes) -> bool:
    """
    Detects if a PE file contains a CLR (.NET) header.
    """
    if type(data) is bytes:
        view = data
    elif type(data) in (bytearray, memoryview):
        view = bytes(data)
    else:
        return False
    result = False
    try:
        if view[:2] != b'MZ':
            return False
        if len(view) < PLR2004N64:
            return False
        pe_offset = struct.unpack('<I', view[60:64])[0]
        if pe_offset <= 0 or pe_offset + 24 > len(view):
            return False
        pe_header = view[pe_offset:pe_offset + 4]
        if pe_header != b'PE\x00\x00':
            return False
        opt_header_offset = pe_offset + 24
        if opt_header_offset + 2 > len(view):
            return False
        magic = struct.unpack('<H', view[opt_header_offset:opt_header_offset + 2])[0]
        if magic not in (PLR2004N267, 523):
            return False
        clr_dir_offset = opt_header_offset + (128 if magic == 267 else 144)
        if clr_dir_offset + 8 > len(view):
            return False
        clr_rva, clr_size = struct.unpack('<II', view[clr_dir_offset:clr_dir_offset + 8])
        result = clr_rva != 0 and clr_size != 0
    except TELEMETRY_FAILURE_ERRORS as e:
        log_error(_core_exception_text('handled exception in error block: ', e))
    return result

def log_bulk_progress(done: object, total: object, file_path: object=None, started_at: object=None, progress_every: object=10) -> None:
    try:
        done_value, done_reason = no_hook_exact_nonnegative_int(done, default=0)
        total_value, total_reason = no_hook_exact_nonnegative_int(total, default=0)
        progress_value, progress_reason = no_hook_exact_nonnegative_int(progress_every, default=1)
        if done_reason or total_reason or progress_reason:
            raise ValueError(done_reason or total_reason or progress_reason)
        progress_value = max(1, progress_value)
        if done_value == 1 or done_value == total_value or done_value % progress_value == 0:
            start_value, start_reason = no_hook_finite_float(
                started_at,
                default=time.time(),
                reason='progress_start_time_rejected',
            )
            if start_reason and started_at is not None:
                raise ValueError(start_reason)
            elapsed = time.time() - start_value
            rate = done_value / elapsed if elapsed > 0 else 0.0
            tail = ''
            if file_path is not None:
                path_text, path_reason = core_path_text(file_path, field_name='progress_file_path')
                if path_reason:
                    tail = ' Current File: <path rejected>'
                else:
                    tail = str.__add__(' Current File: ', Path(path_text).name)
            logging.info(''.join((
                'bulk progress: ',
                int.__str__(done_value),
                '/',
                int.__str__(total_value),
                ' files, ',
                format(rate, '.2f'),
                ' files/s',
                tail,
            )))
    except TELEMETRY_FAILURE_ERRORS as e:
        log_error(_core_exception_text('progress logging failed: ', e))

def log_error(msg: object) -> None:
    if isinstance(msg, BaseException):
        text = no_hook_type_name(msg)
    else:
        text, reason = no_hook_text(msg, unsupported_reason='log_message_rejected')
        if reason:
            text = str.__add__('log_message_rejected:', no_hook_type_name(msg))
    logging.error(text)

def log_odds(p: object) -> object:
    """Convert probability to log-odds safely."""
    value, reason = no_hook_finite_float(p, reason='log_odds_probability_rejected')
    if reason:
        raise ValueError(reason)
    bounded = max(1e-06, min(1.0 - 1e-06, value))
    return math.log(bounded / (1.0 - bounded))

def record_detector_error(detector_name: object, exc: object, context: object=None, **context_fields: object) -> object:
    """Record and log detector failures instead of silently swallowing them.

    In normal batch mode this keeps scanning but exposes the failure in the
    result object. In strict mode it re-raises so broken detectors are fixed
    immediately during development.

    Stage78 real remediation: accept keyword context fields (for example
    ``path=...``) used by scanner exception paths after modularization.
    """
    context_items = no_hook_mapping_items(context)
    if context is None:
        ctx = {}
    elif context_items is None:
        ctx = {'context_unavailable': no_hook_failure('detector_context_rejected', context)}
    else:
        ctx = dict(context_items)
    if context_fields:
        ctx.update(context_fields)
    try:
        entry = record_detector_failure(detector_name, exc, ctx)
    except TELEMETRY_FAILURE_ERRORS as append_error:
        logging.error('detector error recorder failed: %s', no_hook_type_name(append_error))
        entry = {
            'detector': no_hook_type_name(detector_name),
            'error': no_hook_type_name(exc),
            'context': no_hook_materialize(ctx, reason_prefix='detector_context'),
            'time': time.time(),
            'input_evidence': no_hook_failure('detector_error_record_failed', append_error),
        }
    logging.error('Detector failed: %s: %s', entry.get('detector', 'unknown'), entry.get('error', 'unknown'))
    if detector_state_is_strict():
        if isinstance(exc, BaseException):
            raise exc
        raise RuntimeError(entry.get('error', 'detector failure'))
    return entry

def safe_attention_lookup(d: object, key: object) -> object:
    """
    Prevent missing-key crashes in attention maps
    """
    items = no_hook_mapping_items(d)
    key_text, key_reason = no_hook_text(key, unsupported_reason='attention_key_rejected')
    if items is None or key_reason:
        raise ValueError('attention_mapping_rejected' if items is None else key_reason)
    values = {item_key: item for item_key, item in items if type(item_key) is str}
    if key_text not in values:
        return 0.0
    metric, metric_reason = no_hook_finite_float(
        dict.get(values, key_text),
        reason='attention_value_rejected',
    )
    if metric_reason:
        raise ValueError(metric_reason)
    return metric



def sigmoid_odds(x: object) -> object:
    """Sigmoid normalization helper for Hybrid static/model evidence fusion."""
    value, reason = no_hook_finite_float(x, reason='sigmoid_odds_rejected')
    if reason:
        raise ValueError(reason)
    try:
        return 1.0 / (1.0 + math.exp(-value))
    except OverflowError:
        return 0.0 if value < 0 else 1.0
    except TELEMETRY_FAILURE_ERRORS as e:
        log_error(_core_exception_text('handled exception in error block: ', e))
        raise ValueError('sigmoid_odds_failed') from e
