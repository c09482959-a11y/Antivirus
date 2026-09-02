import ctypes
from pathlib import Path, PurePath
from types import MappingProxyType, ModuleType, SimpleNamespace
import hashlib
import logging

_LOGGER = logging.getLogger(__name__)
import os
import re
import shutil
import subprocess
import sys
import zipfile
from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.contracts.library_baseline import library_baseline_has_hard_proof
from Virus_Scan.utils.tagging import normalize_tags, ordered_unique_tags
from Virus_Scan.runtime.engine_hint_runtime import resolve_startup_scan_engine_hint
from Virus_Scan.utils.tagging import norm_lower_set as _norm_lower_set
from Virus_Scan.utils.text_validation import tag_validation_text as _tag_validation_text
from Virus_Scan.utils.text_match import has_any_text as _has_any_text
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
from Virus_Scan.contracts.path_identity import should_include_scan_path as _should_scan_path, DEFAULT_EXCLUDED_DIRS as _DEFAULT_EXCLUDED_DIRS
from Virus_Scan.contracts.env_config import bool_env, env_contains_text
from Virus_Scan.utils.pathing import normalize_scan_path as _canonical_normalize_scan_path, scan_path_text as _canonical_scan_path_text
from Virus_Scan.runtime.config_state import configure_ilspy_path
from Virus_Scan.runtime.path_runtime_state import path_runtime_owner
from Virus_Scan.runtime.scan_integrity_state import scan_integrity_state
from Virus_Scan.runtime.resource_paths import program_root as _owned_program_root, temp_dir as _owned_temp_dir
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_exact_owner_field,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_plain_instance_dict,
    no_hook_sequence_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.core.path_utils import core_path_text

PATH_CONTRACT_EXCEPTIONS = (OSError, ValueError, TypeError, RuntimeError, AttributeError)
PATH_TELEMETRY_EXCEPTIONS = (OSError, RuntimeError, ValueError, TypeError, AttributeError)


def _path_exception_text(prefix: object, exc: object) -> object:
    return str.__add__(prefix, no_hook_type_name(exc))


def _path_safe_text(value: object, *, replacement: object='unavailable') -> object:
    text, reason = no_hook_text(value, unsupported_reason='path_text_rejected')
    if reason or text == '':
        return replacement
    return text


def _module_int_value(module: object, name: object, default: object=0) -> object:
    if type(module) is not ModuleType:
        return default
    value = dict.get(vars(module), name, default)
    return value if type(value) is int else default


def _module_value(module: object, name: object, default: object=None) -> object:
    if type(module) is not ModuleType:
        return default
    return dict.get(vars(module), name, default)


def _candidate_path_from_raw(raw: object) -> object:
    text, reason = core_path_text(raw, field_name='spawn_candidate_path')
    if reason:
        return None
    return Path(text).expanduser().resolve()


def _path_parts_lower(path_text: object, *, as_set: object=False) -> object:
    parts = tuple(part.lower() for part in Path(path_text).parts)
    return set(parts) if as_set else list(parts)


_RENPY_UPDATER_FILENAMES = frozenset({'00updater.rpy', '00updater.rpyc'})
_KNOWN_PYTHON_RUNTIME_LIBRARY_NAMES = frozenset({'bootstrap.py', 'python.py', 'core.py', 'display.py', 'event.py', 'focus.py', 'render.py'})
_KNOWN_PYTHON_RUNTIME_LIBRARY_PATH_HINTS = frozenset({'renpy', 'renpy_base', 'renpy.app', 'renpy-', 'renpy_runtime', 'renpy_runtime_library'})
_RUNTIME_LIBRARY_NAME_HINTS = frozenset({'librenpython.so', 'librenpython.dylib', 'renpython.dll', 'python.dll', 'pythonw.dll', 'python.exe', 'pythonw.exe', 'unityplayer.dll', 'gameassembly.dll', 'mono.dll', 'mono-2.0-bdwgc.dll', 'libmono.so', 'libunity.so', 'libil2cpp.so', 'nw.dll', 'node.dll', 'node.exe', 'ffmpeg.dll', 'libffmpeg.so', 'chrome_elf.dll', 'libcef.dll', 'cefsharp.core.dll', 'cefsharp.dll', 'sdl2.dll', 'openal32.dll', 'vulkan-1.dll'})
_RUNTIME_LIBRARY_PREFIX_HINTS = ('libpython', 'python3', 'librenpython', 'libwinpthread', 'libgcc', 'libstdc++', 'libssp', 'libgomp', 'libmono', 'libunity', 'libil2cpp', 'unityplayer', 'gameassembly', 'mono-', 'node', 'nw', 'chrome_elf', 'libcef', 'cefsharp', 'd3dcompiler', 'sdl2', 'openal', 'avcodec', 'avformat', 'avutil', 'libav', 'libvpx', 'libwebp', 'libpng', 'libjpeg')
_RUNTIME_LIBRARY_PATH_HINTS = frozenset({'lib', 'libs', 'lib64', 'renpy', 'renpy.app', 'py3-linux-x86_64', 'py2-linux', 'py3-windows', 'py2-windows', 'mono', 'monobleedingedge', 'managed', 'plugins', 'nwjs', 'electron', 'cef', 'runtime', 'jre', 'bin'})
_RUNTIME_LIBRARY_EXTS = frozenset({'.dll', '.so', '.dylib', '.pyd', '.node', '.exe'})
_RUNTIME_STRONG_ATTACK_CONTEXT = ('powershell -enc', 'encodedcommand', 'invoke-expression', 'iex(', 'cmd.exe /c', 'wscript.shell', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'schtasks /create', 'wmic process call create', 'createprocessw(', 'createprocessa(', 'writeprocessmemory', 'createremotethread', 'ntcreatethreadex', 'queueuserapc', 'mimikatz', 'sekurlsa', 'minidumpwritedump', 'lsass.exe', 'amsiscanbuffer', 'discord.com/api/webhooks', 'api.telegram.org', '/gate.php', '/panel/', 'reverse shell')
_LIBRARY_BASELINE_NORMAL_TAGS = MappingProxyType({
    'renpy_python_runtime_source': frozenset({'script_execution', 'process_exec', 'bytecode_exec', 'bytecode_eval', 'bytecode_subprocess', 'code_execution', 'pickle_deserialization_context', 'marshal_load', 'marshal_loads', 'payload_decode_candidate', 'obfuscated_script', 'obfuscation_pack', 'packed_or_obfuscated', 'packer_marker', 'persistent_save_data', 'save_archive_access', 'archive_dropper', 'embedded_archive_payload', 'dropper_behavior', 'network_activity', 'network_download', 'network_download_execute', 'process_launch_capability', 'runtime_code_execution_capability', 'runtime_eval_capability', 'runtime_exec_capability', 'runtime_process_capability', 'runtime_serialization_capability', 'runtime_import_capability', 'stage_hit:archive dropper', 'stage_hit:explicit packer marker', 'staged_detection', 'renpy_official_updater', 'renpy_update_download_capability', 'renpy_update_archive_apply_capability', 'renpy_zsync_process_capability', 'persistent_update_state', 'renpy_updater_baseline_v1', 'renpy_updater_dropper_chain_suppressed'}),
    'runtime_engine_binary': frozenset({'script_execution', 'process_exec', 'archive_dropper', 'embedded_archive_payload', 'dropper_behavior', 'network_activity', 'network_download', 'network_download_execute', 'dll_load', 'dll_load_capability', 'assembly_load', 'reflection', 'il_reflection', 'base64', 'payload_decode_candidate', 'encoded_payload_candidate', 'embedded_base64_payload', 'persistence', 'persistent_save_data', 'save_archive_access', 'packer_marker', 'packed_or_obfuscated', 'obfuscation_pack', 'stage_hit:archive dropper', 'stage_hit:explicit packer marker', 'staged_detection'}),
})
_LIBRARY_BASELINE_REPLACEMENTS = MappingProxyType({'script_execution': 'runtime_code_execution_capability', 'code_execution': 'runtime_code_execution_capability', 'bytecode_exec': 'runtime_code_execution_capability', 'bytecode_eval': 'runtime_eval_capability', 'bytecode_subprocess': 'runtime_process_capability', 'process_exec': 'runtime_process_capability', 'network_download': 'runtime_network_capability', 'network_download_execute': 'runtime_network_capability', 'archive_dropper': 'runtime_archive_capability', 'embedded_archive_payload': 'runtime_archive_capability', 'dropper_behavior': 'runtime_archive_capability', 'packer_marker': 'runtime_compression_or_pack_context', 'obfuscation_pack': 'runtime_compression_or_pack_context', 'packed_or_obfuscated': 'runtime_compression_or_pack_context', 'marshal_load': 'runtime_serialization_capability', 'marshal_loads': 'runtime_serialization_capability', 'persistence': 'runtime_state_capability', 'persistent_save_data': 'runtime_state_capability', 'save_archive_access': 'runtime_state_capability', 'stage_hit:archive dropper': 'runtime_stage_hit_suppressed', 'stage_hit:explicit packer marker': 'runtime_stage_hit_suppressed'})
_LIBRARY_BASELINE_HARD_PROOF_TAGS = frozenset({'yara_malware', 'known_bad_hash', 'malware_family', 'confirmed_embedded_pe_payload', 'decoded_pe_payload', 'embedded_pe_payload', 'image_payload_confirmed', 'confirmed_stego_payload', 'mimikatz_credential_dump', 'lsass_access', 'credential_dump_attempt', 'amsi_scanbuffer_patch', 'etw_eventwrite_patch', 'process_injection', 'write_process_memory', 'create_remote_thread', 'remote_thread_create', 'encoded_powershell', 'powershell_exec', 'c2_beacon', 'backdoor_or_c2', 'network_c2', 'c2_or_remote_command'})
_RUNTIME_CAPABILITY_NOISE_TAGS = frozenset({'archive_dropper', 'dropper_behavior', 'embedded_archive_payload', 'base64', 'payload_decode_candidate', 'embedded_base64_payload', 'encoded_payload_candidate', 'dll_hijack', 'dll_sideload', 'dll_load', 'dll_load_capability', 'assembly_load', 'reflection', 'il_reflection', 'network_download', 'network_activity', 'http_upload', 'backdoor_or_c2', 'network_c2', 'remote_command_channel', 'c2_or_remote_command', 'c2_beacon', 'exfiltration', 'network_exfiltration', 'collection', 'input_capture', 'keylogging_behavior', 'clipboard_access', 'macro_office', 'office_macro_execution', 'script_execution', 'memory_allocate', 'memory_allocation', 'memory_access', 'memory_read', 'memory_write', 'memory_protect', 'memory_protection', 'thread_execution', 'process_injection', 'in_memory_execution', 'shellcode_exec', 'anti_debug', 'anti_vm', 'anti_sandbox', 'defense_evasion', 'remote_execution', 'lateral_movement', 'overlay_payload_after_eof', 'obfuscated_script', 'crypto_wallet_pattern', 'crypto_address_display', 'il_invoke', 'IL_INVOKE', 'obfuscation_pack', 'packed_or_obfuscated', 'packer_marker'})
_RUNTIME_PARTIAL_HARD_PROOF_TAGS = frozenset({'yara_malware', 'known_bad_hash', 'malware_family', 'decoded_pe_payload', 'embedded_pe_payload', 'confirmed_embedded_pe_payload', 'encoded_powershell', 'powershell_exec', 'credential_dump_attempt', 'confirmed_browser_wallet_stealer_download_exec', 'mimikatz_credential_dump', 'lsass_access', 'amsi_scanbuffer_patch', 'etw_eventwrite_patch', 'process_injection', 'write_process_memory', 'create_remote_thread', 'remote_thread_create'})
_RUNTIME_PARTIAL_HARD_PROOF_CALLS = frozenset({'virtualallocex', 'writeprocessmemory', 'createremotethread', 'ntcreatethreadex', 'minidumpwritedump'})
def _binary_ext_for_attack_cap(path: object) -> object:
    text, reason = core_path_text(path, field_name='attack_cap_path')
    if reason:
        return False
    result = False
    try:
        result = Path(text).suffix.lower() in {'.exe', '.dll', '.sys', '.ocx', '.scr'}
    except PATH_CONTRACT_EXCEPTIONS:
        result = False
    return result

def _clear_scan_integrity(path: object) -> None:
    key = _umige_path_key(path)
    scan_integrity_state().clear(key)

def _counter_value(v: object) -> object:
    metric, reason = no_hook_finite_float(v, default=0.0)
    if not reason:
        return metric
    items = no_hook_mapping_items(v)
    if items is None:
        return 0.0
    values = {key: value for key, value in items if type(key) is str}
    metric, _ = no_hook_finite_float(values.get('count'), default=0.0)
    return metric

def _get_scan_integrity(path: object) -> object:
    key = _umige_path_key(path)
    return scan_integrity_state().get(key)

def _global_raw_file_id(path: object) -> object:
    text, reason = core_path_text(path, field_name='raw_file_id_path')
    if reason:
        raise ValueError(reason)
    try:
        st = os.stat(text)
        base = '|'.join((str(Path(text).resolve()), int.__str__(int(st.st_size)), int.__str__(int(st.st_mtime_ns))))
    except PATH_CONTRACT_EXCEPTIONS:
        base = str(Path(text).resolve())
    return hashlib.sha256(base.encode('utf-8', errors='ignore')).hexdigest()[:24]

def _is_renpy_bytecode_path(path: object) -> object:
    text, reason = core_path_text(path, field_name='renpy_bytecode_path')
    return False if reason else Path(text).suffix.lower() in {'.rpyc', '.rpyb'}

def _normalized_ext_token(file_path: object) -> object:
    text, reason = core_path_text(file_path, field_name='extension_path')
    if reason:
        return '<unsupported_path>'
    name = Path(text).name.lower().strip()
    suffix = Path(name).suffix.lower().lstrip('.')
    if name in {'global-metadata.dat', 'metadata.dat'}:
        return name
    return suffix or '<no_ext>'

def _process_weight_for_path(path: object) -> object:
    """Heuristic cost used only for ordering global process-queue jobs."""
    text, reason = core_path_text(path, field_name='process_weight_path')
    if reason:
        return 1.0
    weight = 1.0
    try:
        p = Path(text)
        ext = p.suffix.lower()
        size = max(1, int(p.stat().st_size)) if p.exists() else 1
        size_mb = size / (1024.0 * 1024.0)
        if ext in {'.exe', '.dll', '.sys', '.ocx', '.scr', '.com', '.so', '.dylib', '.bin', '.elf'}:
            base = 16.0
        elif ext in {'.py', '.pyc', '.pyo', '.rpy', '.rpyc', '.rpyb', '.js', '.mjs', '.cjs', '.ps1', '.bat', '.cmd', '.vbs', '.hta', '.rb', '.sh', '.lua', '.cs'}:
            base = 12.0
        elif ext in {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.rpa', '.jar', '.pak'}:
            base = 14.0
        elif ext in {'.png', '.jpg', '.jpeg', '.webp', '.gif', '.bmp', '.svg', '.ico', '.icns', '.mp3', '.ogg', '.wav', '.flac', '.mp4', '.avi', '.ttf', '.otf'}:
            base = 8.0
        else:
            base = 5.0
        if ext in {'.rpyc', '.rpyb', '.rpymc', '.pyc'}:
            base += 10.0
        if ext in {'.png', '.webp', '.jpg', '.jpeg'}:
            base += 6.0
        weight = base + min(128.0, size_mb)
    except PATH_CONTRACT_EXCEPTIONS:
        weight = 1.0
    return weight

def _queue_claim_meta_path(claim_path: object) -> object:
    """Sidecar path for active claim ownership metadata.

    Queue job JSON is immutable after pending->active.  Ownership, heartbeat,
    and progress are written to active/<job>.json.claim instead of rewriting
    active/<job>.json.  This removes the transient active-without-queue_info
    race and avoids Windows/Sandboxie locks on live job JSON.
    """
    text, reason = core_path_text(claim_path, field_name='queue_claim_path')
    if reason:
        raise ValueError(reason)
    cp = Path(text)
    return cp.with_name(cp.name + '.claim')

def _queue_failure_diagnostics_dir(queue_dir: object) -> object:
    text, reason = core_path_text(queue_dir, field_name='queue_diagnostics_dir')
    if reason:
        raise ValueError(reason)
    q = Path(text)
    d = q / 'failure_diagnostics'
    try:
        d.mkdir(parents=True, exist_ok=True)
    except PATH_CONTRACT_EXCEPTIONS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except PATH_CONTRACT_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    return d

def _queue_file_identity_for_path(file_path: object) -> object:
    """Stable front-door file identity for original file jobs.

    This is computed before enqueue and does not depend on the transient queue
    filename.  It intentionally uses normalized absolute path rather than file
    contents so the scheduler can deduplicate cheaply before scanning.
    """
    text, reason = core_path_text(file_path, field_name='queue_file_path')
    if reason:
        raise ValueError(reason)
    f_key = os.path.normcase(str(Path(text).resolve()))
    return hashlib.sha256(f_key.encode('utf-8', 'surrogatepass')).hexdigest()[:32]

def _queue_identity_index_cache_key(queue_dir: object, states: object) -> object:
    queue_text, reason = core_path_text(queue_dir, field_name='queue_index_dir')
    if reason:
        raise ValueError(reason)
    state_values = no_hook_sequence_items(states)
    if states is not None and not state_values and type(states) not in (tuple, list, set, frozenset):
        raise ValueError('queue_index_states_rejected')
    normalized_states = []
    for state in state_values:
        text, state_reason = no_hook_text(state, unsupported_reason='queue_index_state_rejected')
        if state_reason:
            raise ValueError(state_reason)
        normalized_states.append(text)
    return (str(Path(queue_text).resolve()), tuple(normalized_states))

def _queue_job_dirs(queue_dir: object) -> object:
    text, reason = core_path_text(queue_dir, field_name='queue_job_dir')
    if reason:
        raise ValueError(reason)
    q = Path(text)
    return (q / 'pending', q / 'active', q / 'done', q / 'failed')

def queue_result_record_name(claim_path: object, file_path: object=None) -> object:
    """Deterministic durable per-file result name.

    Window 10: result record names must not inherit worker ids, pids, retry
    prefixes, or active-claim filenames.  Those values vary with concurrency and
    made file_results/ ordering nondeterministic under saturated queue runs.  The
    durable result record is keyed by normalized file identity only; if two
    workers race for the same file, atomic replace converges on the same
    authority path rather than creating order-dependent siblings.
    """
    identity_value = claim_path if file_path is None else file_path
    raw_text, reason = core_path_text(identity_value, field_name='queue_result_path')
    if reason:
        raise ValueError(reason)
    raw = os.path.normcase(str(Path(raw_text).resolve()))
    digest = hashlib.sha256(raw.encode('utf-8', 'surrogatepass')).hexdigest()[:32]
    h = digest.translate(str.maketrans('0123456789abcdef', 'abcdefghijklmnop'))
    stem = Path(raw_text).name or 'unknown'
    safe = ''.join((ch if ch.isalnum() or ch in '._-' else '_' for ch in stem)).strip('._ ')[:96] or 'unknown'
    return h + '_' + safe + '.result.json'

def _queue_retire_dir(queue_dir: object) -> object:
    """Directory containing one-shot idle-worker retire tokens for elastic pool shrink."""
    text, reason = core_path_text(queue_dir, field_name='queue_retire_dir')
    if reason:
        raise ValueError(reason)
    d = Path(text) / 'retire'
    try:
        d.mkdir(parents=True, exist_ok=True)
    except PATH_CONTRACT_EXCEPTIONS:
        try:
            d.mkdir(parents=True, exist_ok=True)
        except PATH_CONTRACT_EXCEPTIONS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except PATH_CONTRACT_EXCEPTIONS as _umige_reporting_exc:
                _ = _umige_reporting_exc
    return d

def _raw_stage_cache_key(job: object) -> object:
    items = no_hook_mapping_items(job)
    if items is None:
        return None
    values = {key: value for key, value in items if type(key) is str}
    path_text, reason = core_path_text(values.get('file'), field_name='raw_stage_file')
    collector, collector_reason = no_hook_text(values.get('collector'), unsupported_reason='raw_stage_collector_rejected')
    start, start_reason = no_hook_exact_nonnegative_int(values.get('start'), default=0)
    size, size_reason = no_hook_exact_nonnegative_int(values.get('size'), default=0)
    if reason or collector_reason or start_reason or size_reason:
        return None
    cache_key = None
    try:
        path = str(Path(path_text).resolve())
        st = os.stat(path)
        cache_key = (path, int(st.st_size), int(st.st_mtime_ns), collector, start, size)
    except PATH_CONTRACT_EXCEPTIONS:
        cache_key = None
    return cache_key

def _set_scan_integrity(path: object, meta: object) -> None:
    key = _umige_path_key(path)
    if meta is None:
        value = {}
    else:
        items = no_hook_mapping_items(meta)
        if items is None:
            value = {
                'unavailable_reason': 'scan_integrity_meta_rejected',
                'value_type': no_hook_type_name(meta),
            }
        else:
            value = dict(items)
    scan_integrity_state().set(key, value)

def _umige_candidate_dir_from_exe_path(path: object) -> object:
    """Return parent directory for a real launcher path, rejecting extraction dirs."""
    text, reason = core_path_text(path, field_name='launcher_path')
    if reason:
        return None
    candidate_dir = None
    try:
        p = Path(text).expanduser()
        try:
            p = p.resolve()
        except PATH_CONTRACT_EXCEPTIONS:
            p = Path(PurePath.as_posix(p)).resolve()
        if not p.exists() or not p.is_file():
            return None
        if _umige_path_looks_like_nuitka_onefile_temp(p):
            return None
        if p.suffix.lower() in {'.py', '.pyw'} and p.parent.name == 'Virus_Scan' and (p.parent.parent / 'Virus_Scan').is_dir():
            return str(p.parent.parent)
        if p.suffix.lower() in {'.exe', '.py', '.pyw'}:
            candidate_dir = str(p.parent)
    except PATH_CONTRACT_EXCEPTIONS:
        candidate_dir = None
    return candidate_dir

def _umige_path_key(path: object) -> object:
    text, reason = core_path_text(path, field_name='path_key')
    if reason:
        raise ValueError(reason)
    return str(Path(text).resolve())

def _umige_path_looks_like_nuitka_onefile_temp(path: object) -> object:
    """Best-effort guard: true for Nuitka extraction paths like Temp\\OneFile\\<pid>."""
    text, reason = core_path_text(path, field_name='onefile_path')
    if reason:
        return False
    result = False
    try:
        parts = [part.lower() for part in Path(text).parts]
        result = 'onefile' in parts and any((part == 'temp' for part in parts))
    except PATH_CONTRACT_EXCEPTIONS:
        result = False
    return result

def _umige_base_before_nuitka_onefile_temp(path: object) -> object:
    """Return the scanner-owned base before a Nuitka Temp/OneFile extraction segment.

    This helper is deliberately narrow: it converts paths such as
    <root>/Temp/OneFile/<pid>/Virus_Scanner.exe back to <root>.  Invalid
    or non-extraction paths return None so callers can continue through their
    normal deterministic path-resolution chain.
    """
    text, reason = core_path_text(path, field_name='onefile_base_path')
    if reason:
        return None
    base = None
    try:
        p = Path(text).expanduser()
        parts = list(p.parts)
        lowered = [part.lower() for part in parts]
        for idx in range(len(lowered) - 1):
            if lowered[idx] == 'temp' and lowered[idx + 1] == 'onefile':
                if idx == 0:
                    return None
                root = Path(*parts[:idx])
                if root.exists() and root.is_dir():
                    return str(root.resolve())
                return str(root)
    except PATH_CONTRACT_EXCEPTIONS as exc:
        _ = exc
    return base

def _umige_running_inside_sandboxie() -> object:
    """Best-effort Sandboxie detection for subprocess console handling.

    Sandboxie can raise ConsoleInit errors when CREATE_NO_WINDOW is used.
    Keep process-group isolation, but avoid hidden-console creation flags when
    the scan is running under Sandboxie/Sbie.
    """
    if os.name != 'nt':
        return False
    result = False
    try:
        if bool_env('UMIGE_FORCE_SANDBOXIE', default=False):
            return True
        if bool_env('UMIGE_DISABLE_SANDBOXIE_CONSOLE_POLICY', default=False):
            return False
        if env_contains_text('sandboxie', 'sbie'):
            return True
        try:
            k32 = ctypes.windll.kernel32
            for dll in ('SbieDll.dll', 'SbieDllX64.dll'):
                try:
                    if k32.GetModuleHandleW(dll):
                        return True
                except PATH_CONTRACT_EXCEPTIONS as _umige_suppressed_exc:
                    try:
                        record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
                    except PATH_CONTRACT_EXCEPTIONS as _umige_reporting_exc:
                        _ = _umige_reporting_exc
        except PATH_CONTRACT_EXCEPTIONS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except PATH_CONTRACT_EXCEPTIONS as _umige_reporting_exc:
                _ = _umige_reporting_exc
    except PATH_CONTRACT_EXCEPTIONS:
        result = False
    return result

def _umige_runtime_base_dir() -> object:
    """Return the canonical runtime writable/resource root.

    Runtime path ownership is centralized in Virus_Scan.runtime.resource_paths.
    This caller boundary delegates directly to the canonical runtime owner so
    pytest/python launch wrappers do not become scanner writable roots.
    """
    try:
        return str(_owned_program_root())
    except PATH_CONTRACT_EXCEPTIONS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except PATH_CONTRACT_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    return str(Path(__file__).resolve().parents[2])



def runtime_base_dir() -> object:
    """Return the canonical runtime writable/resource root through a public path contract."""
    return _umige_runtime_base_dir()

def _umige_runtime_temp_dir() -> object:
    """Return <scanner/script/exe root>\\Temp and create it.

    This is the only scanner-owned transient root.  It is intentionally
    derived from _umige_runtime_base_dir() so it follows the launched script or
    compiled EXE location.  It must not hardcode folder names such as Batch,
    and it must not use Nuitka's onefile extraction directory or Windows
    AppData temp.
    """
    owner_temp = None
    try:
        owner_temp = _owned_temp_dir()
    except PATH_CONTRACT_EXCEPTIONS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('runtime_temp_dir_owner_failed', _umige_suppressed_exc, domain='runtime')
        except PATH_CONTRACT_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    if owner_temp is not None:
        return owner_temp
    root = Path(_umige_runtime_base_dir()).resolve()
    temp_root = root / 'Temp'
    temp_root.mkdir(parents=True, exist_ok=True)
    return temp_root

def _umige_runtime_temp_path(name: object) -> object:
    """Return a sanitized child of <scanner/script/exe root>\\Temp."""
    raw, reason = no_hook_text(
        name,
        missing_reason='runtime_temp_name_missing',
        unsupported_reason='runtime_temp_name_rejected',
    )
    if reason or raw == '':
        raw = 'umige.tmp'
    safe = ''.join((ch if ch.isalnum() or ch in '._-' else '_' for ch in raw)).strip('._ ')
    if not safe:
        safe = 'umige.tmp'
    return _umige_runtime_temp_dir() / safe

def _umige_subprocess_stdin() -> object:
    """Sandboxie-safe stdin choice for helper/worker subprocesses."""
    try:
        if os.name == 'nt' and _umige_running_inside_sandboxie():
            return None
    except PATH_CONTRACT_EXCEPTIONS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except PATH_CONTRACT_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    return subprocess.DEVNULL

def _umige_windows_creationflags(*, worker: object=False, helper: object=False) -> object:
    """Return Windows subprocess flags that prevent child console events from
    propagating back into the parent/batch wrapper.

    Sandboxie process-group requirement: CREATE_NEW_PROCESS_GROUP is kept, but
    CREATE_NO_WINDOW is skipped inside Sandboxie because it can trigger
    Sandboxie ConsoleInit failures.

    This is queue infrastructure only. It does not change scan scoring, tags,
    models, YARA weights, baselines, or evidence handling.
    """
    del helper, worker  # Explicitly unused contract parameters.
    if os.name != 'nt':
        return 0
    flags = 0
    try:
        flags |= _module_int_value(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
    except PATH_CONTRACT_EXCEPTIONS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except PATH_CONTRACT_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    if not _umige_running_inside_sandboxie():
        try:
            flags |= _module_int_value(subprocess, 'CREATE_NO_WINDOW', 0)
        except PATH_CONTRACT_EXCEPTIONS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except PATH_CONTRACT_EXCEPTIONS as _umige_reporting_exc:
                _ = _umige_reporting_exc
    return flags

def apply_engine_runtime_capability_tags(tags: object, path: object=None, strings_blob: object='') -> object:
    """Final Ren'Py runtime source downgrade for display/input/save capabilities."""
    if not is_renpy_engine_runtime_source_path(path, strings_blob):
        return ordered_unique_tags(tags)
    replace = {'input_capture': 'input_event_handling', 'keylogging_behavior': 'input_event_handling', 'user_activity_monitoring': 'input_event_handling', 'screenshot_capture': 'screen_capture_capability', 'screen_capture': 'screen_capture_capability', 'collection': 'collection_capability', 'network_activity': 'network_capability', 'persistent_save_data': 'runtime_state_capability', 'renpy_save_location': 'runtime_state_capability'}
    hard = library_baseline_has_hard_proof(tags, strings_blob)
    out = []
    changed = False
    for t in tags or []:
        low = str(t).lower()
        if low in replace and (not hard):
            out.append(replace[low])
            changed = True
        else:
            out.append(t)
    out.extend(['renpy_runtime_library', 'renpy_display_runtime', 'engine_capability_context'])
    if changed:
        out.append('renpy_runtime_capability_downgraded')
    return ordered_unique_tags(out)

def collect_target_files(root: object, file_list_path: object=None) -> object:
    """Collect scan targets deterministically while honoring exclusions.

    Core no longer imports routing for path inclusion.  The exclusion predicate is
    an import-light contract, so path collection remains infrastructure-owned.
    """
    root_text, root_reason = core_path_text(root, field_name='scan_root')
    if root_reason:
        raise ValueError(root_reason)
    if file_list_path is not None:
        list_text, list_reason = core_path_text(file_list_path, field_name='file_list_path')
        if list_reason:
            raise ValueError(list_reason)
        out = []
        try:
            with Path(list_text).open('r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    item = line.rstrip('\n')
                    if item and Path(item).is_file() and _should_scan_path(item, scan_root=root_text):
                        out.append(item)
        except PATH_CONTRACT_EXCEPTIONS as e:
            log_error(_path_exception_text(str.__add__('file list load failed: ', str.__add__(list_text, ': ')), e))
        return sorted(dict.fromkeys(out), key=lambda item: str(item).replace("\\", "/").casefold())
    if Path(root_text).is_file():
        return [root_text] if _should_scan_path(root_text, scan_root=str(Path(root_text).resolve().parent)) else []
    all_files = []
    for r, dirs, files in os.walk(root_text):
        dirs[:] = sorted((d for d in dirs if d not in _DEFAULT_EXCLUDED_DIRS and _should_scan_path(str(Path(r) / d), scan_root=root_text)))
        for name in sorted(files):
            path = str(Path(r) / name)
            if _should_scan_path(path, scan_root=root_text):
                all_files.append(path)
    return sorted(all_files, key=lambda item: str(item).replace("\\", "/").casefold())

def configure_runtime_engine_and_ilspy(args: object) -> None:
    """Apply CLI/runtime options after argparse and before scanning."""
    owner = path_runtime_owner()
    args_state = no_hook_plain_instance_dict(args)
    args_state = {} if args_state is None else args_state
    cli_engine_hint, engine_reason = no_hook_text(
        dict.get(args_state, 'engine'),
        missing_reason='cli_engine_hint_missing',
        unsupported_reason='cli_engine_hint_rejected',
    )
    cli_engine_hint = 'auto' if engine_reason or not cli_engine_hint.strip() else cli_engine_hint.lower().strip()
    scan_engine_hint, scan_engine_hint_context = resolve_startup_scan_engine_hint(
        dict.get(args_state, 'dir'),
        cli_engine_hint,
    )
    owner.configure_engine(cli_engine_hint, scan_engine_hint, scan_engine_hint_context)
    ilspy_arg = dict.get(args_state, 'ilspy')
    ilspy_path_arg = dict.get(args_state, 'ilspy_path')
    ilspy_text, ilspy_reason = no_hook_text(
        ilspy_arg,
        missing_reason='ilspy_option_missing',
        unsupported_reason='ilspy_option_rejected',
    )
    if ilspy_path_arg is None:
        ilspy_path_text, ilspy_path_reason = '', 'ilspy_path_missing'
    else:
        ilspy_path_text, ilspy_path_reason = core_path_text(
            ilspy_path_arg,
            field_name='ilspy_path',
            allow_empty=True,
        )
    enable_ilspy = (
        (not ilspy_reason and ilspy_text != '')
        or (not ilspy_path_reason and ilspy_path_text != '')
    )
    cli_ilspy_path = None
    if not ilspy_reason and ilspy_text.lower() not in {'', 'auto', 'true', '1', 'yes'}:
        cli_ilspy_path = ilspy_text
    default_ilspy_path = str(Path(_umige_runtime_base_dir()) / 'ilspycmd.exe')
    selected_ilspy_path = (
        ilspy_path_text
        if not ilspy_path_reason and ilspy_path_text
        else cli_ilspy_path or default_ilspy_path
    )
    ilspy_path = configure_ilspy_path(selected_ilspy_path)
    use_ilspy = bool(enable_ilspy and ilspy_path and Path(ilspy_path).exists())
    dump_root_text = None
    dump_arg = dict.get(args_state, 'ilspy_dump')
    if dump_arg is not None:
        dump_text, dump_reason = core_path_text(dump_arg, field_name='ilspy_dump_path')
        try:
            if dump_reason:
                raise ValueError(dump_reason)
            dump_root = Path(dump_text).expanduser().resolve()
            dump_root.mkdir(parents=True, exist_ok=True)
            dump_root_text = PurePath.__str__(dump_root)
        except PATH_CONTRACT_EXCEPTIONS as e:
            log_error(_path_exception_text('ILSpy dump path unavailable; using default dump location: ', e))
            dump_root_text = None
    timeout_sec, timeout_reason = no_hook_exact_nonnegative_int(
        dict.get(args_state, 'ilspy_timeout'),
        default=60,
    )
    timeout_sec = 60 if timeout_reason else max(1, timeout_sec)
    owner.configure_ilspy(path=ilspy_path, use_ilspy=use_ilspy, timeout_sec=timeout_sec, dump_root=dump_root_text)
    snapshot = owner.snapshot()
    _LOGGER.info(''.join((
        'Engine hint: cli=',
        _path_safe_text(snapshot.cli_engine_hint, replacement='auto'),
        ' resolved=',
        _path_safe_text(snapshot.scan_engine_hint, replacement='auto'),
        ' context=',
        _path_safe_text(snapshot.scan_engine_hint_context, replacement='unavailable'),
    )))
    if snapshot.use_ilspy:
        _LOGGER.info(str.__add__('ILSpy enabled for .NET .exe/.dll after CLR precheck: ', _path_safe_text(snapshot.ilspy_path, replacement='unavailable')))
        if snapshot.ilspy_dump_root:
            _LOGGER.info(str.__add__('ILSpy dump path: ', _path_safe_text(snapshot.ilspy_dump_root, replacement='unavailable')))
    elif enable_ilspy:
        _LOGGER.info(''.join((
            'ILSpy requested but executable was not found: ',
            _path_safe_text(snapshot.ilspy_path, replacement='unavailable'),
            '; .NET .exe/.dll will use static metadata analysis',
        )))
    else:
        _LOGGER.info('ILSpy disabled; .NET .exe/.dll will use static metadata analysis')

def enforce_runtime_library_post_derive_gate(tags: object, path: object=None, strings_blob: object='') -> object:
    """Final safety pass: prevent derive_behavior_tags() from recreating runtime FP chains."""
    if not (is_runtime_or_engine_library_path(path) or is_known_python_runtime_library_path(path, strings_blob)):
        return ordered_unique_tags(tags)
    text = _tag_validation_text(strings_blob)
    tagset = {str(t).lower() for t in tags or []}
    hard_keep = {'yara_malware', 'known_bad_hash', 'malware_family', 'confirmed_embedded_pe_payload', 'decoded_pe_payload', 'embedded_pe_payload', 'mimikatz_credential_dump', 'lsass_access', 'credential_dump_attempt', 'amsi_scanbuffer_patch', 'etw_eventwrite_patch', 'write_process_memory', 'create_remote_thread', 'remote_thread_create', 'process_injection', 'encoded_powershell', 'powershell_exec'}
    strong_runtime_proof = bool(tagset & hard_keep) or _has_any_text(text, _RUNTIME_STRONG_ATTACK_CONTEXT)
    if strong_runtime_proof:
        return ordered_unique_tags(tags)
    block = set(_RUNTIME_CAPABILITY_NOISE_TAGS) | {'network_exfiltration', 'remote_execution', 'lateral_movement', 'credential_access', 'process_injection', 'c2_or_remote_command', 'c2_beacon', 'backdoor_or_c2', 'network_c2', 'remote_command_channel'}
    cleaned = []
    removed = False
    for t in tags or []:
        low = str(t).lower()
        if low in block:
            removed = True
            continue
        cleaned.append(t)
    if is_known_python_runtime_library_path(path, strings_blob):
        cleaned.append('python_runtime_library')
        cleaned.append('renpy_runtime_library')
    elif is_python_runtime_binary_path(path):
        cleaned.append('python_runtime_binary')
    else:
        cleaned.append('engine_runtime_library')
    if removed:
        cleaned.append('runtime_capability_noise_suppressed')
        cleaned.append('runtime_post_derive_gate')
    return ordered_unique_tags(cleaned)

def get_current_script_path_for_spawn() -> object:
    """Return the single canonical launcher used for scheduler child processes.

    Source-mode direct API clients are not scanner launchers.  Their
    ``sys.argv[0]`` may name a test, benchmark, notebook, or embedding program;
    relaunching it would recursively execute caller code instead of entering the
    queue-child runtime.  Source mode therefore resolves only the repository's
    canonical ``build_entry_umige.py``.  Compiled mode resolves only the visible
    executable, including the bounded Nuitka onefile recovery path.
    """
    compiled = vars(sys).get('frozen') is True or '__compiled__' in globals()
    if compiled:
        candidates = []
        compiled_state = globals().get('__compiled__')
        if type(compiled_state) is SimpleNamespace:
            raw = vars(compiled_state).get('original_argv0')
            try:
                candidate = _candidate_path_from_raw(raw)
                if candidate is not None:
                    candidates.append(candidate)
            except PATH_CONTRACT_EXCEPTIONS as exc:
                _ = exc
        try:
            candidate = _candidate_path_from_raw(_module_value(sys, 'executable'))
            if candidate is not None:
                candidates.append(candidate)
        except PATH_CONTRACT_EXCEPTIONS as exc:
            _ = exc
        for candidate in candidates:
            try:
                if candidate.exists() and candidate.is_file() and not _umige_path_looks_like_nuitka_onefile_temp(candidate):
                    return candidate
            except PATH_CONTRACT_EXCEPTIONS:
                continue
        for candidate in candidates:
            try:
                derived = _umige_base_before_nuitka_onefile_temp(candidate)
                if derived:
                    executable = Path(derived) / 'Virus_Scanner.exe'
                    if executable.exists() and executable.is_file():
                        return executable.resolve()
            except PATH_CONTRACT_EXCEPTIONS:
                continue
        raise FileNotFoundError(
            'Cannot resolve canonical compiled scanner launcher; executable='
            + _path_safe_text(_module_value(sys, 'executable'), replacement='unavailable')
        )

    source_launcher = Path(__file__).resolve().parents[2] / 'build_entry_umige.py'
    try:
        if source_launcher.exists() and source_launcher.is_file():
            return source_launcher.resolve()
    except PATH_CONTRACT_EXCEPTIONS as exc:
        _ = exc
    raise FileNotFoundError(
        'Cannot resolve canonical source scanner launcher; expected='
        + PurePath.__str__(source_launcher)
    )

def get_ilspy_dump_root(scan_file: object) -> object:
    """
    Dump directory is created inside the parent directory of the scan folder.
    Example: scan target F:/Temp/Game -> F:/Temp/dump
    """
    owner = path_runtime_owner()
    configured = owner.ilspy_dump_root()
    if configured:
        return configured
    scan_text, scan_reason = core_path_text(scan_file, field_name='ilspy_scan_path')
    dump_root = None
    try:
        if scan_reason:
            raise ValueError(scan_reason)
        root = Path(scan_text).resolve()
        scan_folder = root if root.is_dir() else root.parent
        dump_root = scan_folder.parent / 'dump'
        dump_root.mkdir(parents=True, exist_ok=True)
    except PATH_CONTRACT_EXCEPTIONS:
        dump_root = Path(_umige_runtime_base_dir()).resolve() / 'dump'
        dump_root.mkdir(parents=True, exist_ok=True)
    return owner.set_ilspy_dump_root(str(dump_root))

def get_library_behavior_baseline_profile(path: object=None, strings_blob: object='') -> object:
    """Return a baseline profile for known runtime/library files, if any."""
    profile = None
    try:
        if is_known_python_runtime_library_path(path, strings_blob):
            profile = {'name': 'renpy_python_runtime_source', 'normal_tags': set(_LIBRARY_BASELINE_NORMAL_TAGS['renpy_python_runtime_source']), 'identity_tags': ['python_runtime_library', 'renpy_runtime_library', 'library_behavior_baseline:renpy_python_runtime_source']}
        elif is_runtime_or_engine_library_path(path):
            profile = {'name': 'runtime_engine_binary', 'normal_tags': set(_LIBRARY_BASELINE_NORMAL_TAGS['runtime_engine_binary']), 'identity_tags': ['engine_runtime_library', 'library_behavior_baseline:runtime_engine_binary']}
    except PATH_CONTRACT_EXCEPTIONS:
        profile = None
    return profile

def get_python_executable_for_spawn() -> object:
    """Return a valid Python executable path for child process shards.

    Prefer sys.executable so the child uses the same interpreter/environment as
    the parent. Fall back to py/python only if sys.executable is unavailable.
    """
    candidates = []
    try:
        if sys.executable:
            candidates.append(Path(sys.executable))
    except PATH_CONTRACT_EXCEPTIONS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except PATH_CONTRACT_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    for name in ('py', 'python', 'python3'):
        try:
            found = shutil.which(name)
            if found:
                candidates.append(Path(found))
        except PATH_CONTRACT_EXCEPTIONS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except PATH_CONTRACT_EXCEPTIONS as _umige_reporting_exc:
                _ = _umige_reporting_exc
    for cand in candidates:
        try:
            if str(cand).lower() in {'py', 'python', 'python3'}:
                return str(cand)
            if cand.exists() and cand.is_file():
                return str(cand.resolve())
        except PATH_CONTRACT_EXCEPTIONS:
            continue
    raise FileNotFoundError(str.__add__('Cannot resolve Python executable for shard relaunch; sys.executable=', _path_safe_text(_module_value(sys, 'executable'), replacement='unavailable')))


def _stable_entity_id(kind: object, value: object) -> object:
    kind_text, kind_reason = no_hook_text(kind, unsupported_reason='entity_kind_rejected')
    value_text, value_reason = no_hook_text(value, unsupported_reason='entity_value_rejected')
    if kind_reason:
        kind_text = 'entity'
    if value_reason:
        value_text = no_hook_type_name(value)
    identity_text = str.__add__(kind_text, str.__add__(':', value_text))
    digest = hashlib.sha256(identity_text.encode('utf-8', 'surrogatepass')).hexdigest()[:24]
    return str.__add__(kind_text, str.__add__(':', digest))


def infer_behavioral_entities(path: object=None, tags: object=None, metadata: object=None) -> object:
    """Infer lightweight behavioral entities for causal continuity metadata.

    This does not execute or extract payloads. It creates stable identifiers for
    the current file, decoded/payload-like indicators, network indicators, and
    execution indicators so chains can be reasoned about as entity flow instead
    of plain co-occurrence.
    """
    del metadata  # Explicitly unused contract parameters.
    tags = normalize_tags(tags)
    tagset = {tag.lower() for tag in tags}
    entities = []
    path_text = ''
    path_reason = ''
    if path is not None:
        path_text, path_reason = core_path_text(path, field_name='behavioral_entity_path')
    try:
        if path_reason:
            entities.append({
                'entity_id': _stable_entity_id('file_unavailable', no_hook_type_name(path)),
                'entity_type': 'file',
                'value_hint': None,
                'unavailable_reason': path_reason,
                'value_type': no_hook_type_name(path),
            })
        elif path_text:
            entities.append({'entity_id': _stable_entity_id('file', str(Path(path_text).resolve())), 'entity_type': 'file', 'value_hint': Path(path_text).name})
        if tagset & {'decoded_base64_blob', 'encoded_payload', 'payload_decode_candidate', 'embedded_gzip_payload', 'compressed_payload_candidate'}:
            entities.append({'entity_id': _stable_entity_id('payload_decode_candidate', path_text + ':' + ','.join(sorted(tagset))), 'entity_type': 'payload_decode_candidate', 'value_hint': 'decoded_or_compressed_payload'})
        if tagset & {'network_download', 'network_activity', 'url_present', 'reference_url', 'http_upload', 'network_exfiltration'}:
            entities.append({'entity_id': _stable_entity_id('network_ioc', path_text + ':network'), 'entity_type': 'network_ioc', 'value_hint': 'network_or_url_indicator'})
        if tagset & {'process_exec', 'script_execution', 'shell_exec_abuse', 'powershell_exec', 'wscript_exec', 'mshta_exec', 'rundll32_proxy_execution'}:
            entities.append({'entity_id': _stable_entity_id('execution', path_text + ':exec'), 'entity_type': 'execution_context', 'value_hint': 'execution_capability'})
        if tagset & {'file_write', 'dropper', 'archive_member', 'persistent_save_data', 'file_rename_delete'}:
            entities.append({'entity_id': _stable_entity_id('written_artifact', path_text + ':write'), 'entity_type': 'written_artifact', 'value_hint': 'write_or_drop_candidate'})
    except PATH_CONTRACT_EXCEPTIONS as e:
        log_error(_path_exception_text('behavioral entity inference failed: ', e))
    dedup = {}
    for entity in entities:
        dedup[entity.get('entity_id')] = entity
    return [dict.get(dedup, key) for key in tuple(dict.keys(dedup))]

def is_known_python_runtime_library_path(path: object=None, strings_blob: object='') -> object:
    """
    Identify Python-source runtime libraries shipped by Ren'Py, especially
    renpy/bootstrap.py and renpy/python.py. These files define the interpreter
    runtime handoff, AST/bytecode compile/eval helpers, rollback store machinery, and
    launcher/bootstrap behavior, so exec/eval/marshal/subprocess/import strings
    are expected library capabilities rather than direct malware intent.

    This is deliberately not a blanket trust rule: it only identifies the
    library context. Hard anchors such as YARA malware, known-bad hash, C2 IOC,
    injection, credential theft, or confirmed embedded payload still bypass the
    baseline gate and score normally.
    """
    path_text = ''
    if path is not None:
        path_text, path_reason = core_path_text(path, field_name='python_runtime_library_path', allow_empty=True)
        if path_reason:
            path_text = ''
    result = False
    try:
        strings_missing = strings_blob is None or (type(strings_blob) is str and strings_blob == '')
        if path_text == '' and strings_missing:
            return False
        name = Path(path_text).name.lower() if path_text else ''
        parts = set(_path_parts_lower(path_text, as_set=True)) if path_text else set()
        if is_renpy_engine_runtime_source_path(path, strings_blob):
            return True
        if name not in _KNOWN_PYTHON_RUNTIME_LIBRARY_NAMES:
            return False
        if any(('renpy' in part for part in parts)) or parts & _KNOWN_PYTHON_RUNTIME_LIBRARY_PATH_HINTS:
            return True
        text = _tag_validation_text(strings_blob)
        if not text:
            return False
        if name == 'bootstrap.py':
            return (
                (
                    'tom rothamel' in text
                    and 'renpy.arguments.bootstrap' in text
                    and ('renpy.import_all' in text)
                    and ('path_to_gamedir' in text)
                )
                or (
                    'def bootstrap(renpy_base)' in text
                    and 'import renpy.config' in text
                    and ('renpy.main.main' in text)
                )
            )
        if name == 'python.py':
            return (
                (
                    'tom rothamel' in text
                    and 'def py_compile' in text
                    and ('def py_exec' in text)
                    and ('store_dicts' in text)
                    and ('rollback' in text)
                )
                or (
                    'class storedict' in text
                    and 'def py_exec_bytecode' in text
                    and ('marshal.loads' in text)
                    and ('renpy.ast.pyexpr' in text)
                )
            )
    except PATH_CONTRACT_EXCEPTIONS:
        result = False
    return result

def is_python_runtime_binary_path(path: object=None) -> object:
    """
    Identify bundled Python interpreter/runtime binaries such as libpython3.12.dll,
    python.exe/pythonw.exe, and libpython*.so/dylib.

    These files legitimately contain strings/API names for zip/base64/DLL loading,
    sockets, input handling, extension loading, and import machinery. Those are runtime
    capabilities, not proof that the game/app is executing a malware chain.
    """
    path_text = ''
    if path is not None:
        path_text, path_reason = core_path_text(path, field_name='python_runtime_binary_path', allow_empty=True)
        if path_reason:
            path_text = ''
    result = False
    try:
        if path_text == '':
            return False
        p = Path(path_text)
        name = p.name.lower()
        ext = p.suffix.lower()
        parts = {x.lower() for x in p.parts}
        if is_known_python_runtime_library_path(path):
            return True
        if ext not in {'.dll', '.exe', '.so', '.dylib', ''}:
            return False
        if name in {'python', 'pythonw', 'python.exe', 'pythonw.exe'}:
            return True
        if re.match('^(?:lib)?python(?:\\d+(?:\\.\\d+)*|\\d{2,4})?(?:_d)?\\.(?:dll|so|dylib|exe)$', name):
            return True
        if re.match('^librenpython(?:\\d+(?:\\.\\d+)*)?\\.(?:so|dylib|dll)$', name):
            return True
        if name in {'python', 'pythonw'} and any(part.startswith(('py3', 'python3')) for part in parts):
            return True
    except PATH_CONTRACT_EXCEPTIONS:
        result = False
    return result

def is_renpy_engine_runtime_source_path(path: object=None, strings_blob: object='') -> object:
    """Identify Ren'Py engine/runtime source modules whose input/display/screenshot/save behavior is normal engine capability."""
    path_text = ''
    if path is not None:
        path_text, path_reason = core_path_text(path, field_name='renpy_engine_source_path', allow_empty=True)
        if path_reason:
            path_text = ''
    result = False
    try:
        name = Path(path_text).name.lower() if path_text else ''
        parts = _path_parts_lower(path_text) if path_text else []
        text = _tag_validation_text(strings_blob)
        if name == 'core.py' and 'renpy' in parts and ('display' in parts):
            return True
        if name == 'core.py' and 'tom rothamel' in text and ('pygame.event' in text) and ('class displayable' in text) and ('class interface' in text):
            return True
        if name in {'focus.py', 'render.py', 'layout.py', 'screen.py', 'im.py', 'module.py'} and 'renpy' in parts and ('display' in parts):
            return True
    except PATH_CONTRACT_EXCEPTIONS:
        result = False
    return result

def is_renpy_official_updater_path(path: object=None, strings_blob: object='') -> object:
    """Detect Ren'Py's official 00updater runtime script by path or source markers."""
    path_text = ''
    if path is not None:
        path_text, path_reason = core_path_text(path, field_name='renpy_updater_path', allow_empty=True)
        if path_reason:
            path_text = ''
    result = False
    try:
        name = Path(path_text).name.lower() if path_text else ''
        parts = set(_path_parts_lower(path_text, as_set=True)) if path_text else set()
        text = _tag_validation_text(strings_blob)
        if name not in _RENPY_UPDATER_FILENAMES:
            return False
        if 'renpy' in parts or 'common' in parts:
            return True
        result = 'tom rothamel' in text and ('class updater' in text or 'zsync' in text or 'zsync_path' in text) and ('downloadneeded' in text or 'requests' in text or 'tarfile' in text or ('zsync_update' in text))
    except PATH_CONTRACT_EXCEPTIONS:
        result = False
    return result

def is_runtime_or_engine_library_path(path: object=None) -> object:
    """
    Identify bundled runtime/engine binaries that naturally expose scary APIs/strings.

    This is intentionally narrower than "every DLL/SO": it catches known Python/Ren'Py,
    Unity/Mono/IL2CPP, NW.js/Electron/Chromium, and common multimedia/input runtime libs.
    Unknown DLL/SO files are handled by behavior gating, but not blanket-suppressed.
    """
    path_text = ''
    if path is not None:
        path_text, path_reason = core_path_text(path, field_name='runtime_engine_library_path', allow_empty=True)
        if path_reason:
            path_text = ''
    result = False
    try:
        if is_python_runtime_binary_path(path) or is_known_python_runtime_library_path(path):
            return True
        if path_text == '':
            return False
        p = Path(path_text)
        name = p.name.lower()
        stem = p.stem.lower()
        ext = p.suffix.lower()
        if ext not in _RUNTIME_LIBRARY_EXTS:
            return False
        parts = {x.lower() for x in p.parts}
        if name in _RUNTIME_LIBRARY_NAME_HINTS:
            return True
        if any((name.startswith(prefix) or stem.startswith(prefix) for prefix in _RUNTIME_LIBRARY_PREFIX_HINTS)):
            if parts & _RUNTIME_LIBRARY_PATH_HINTS or ext in {'.so', '.dylib', '.pyd', '.node'}:
                return True
        if name.startswith('python') and ext in {'.dll', '.exe', '.so', '.dylib'}:
            return True
        if ('renpy' in name or 'renpython' in name) and ext in {'.dll', '.so', '.dylib', '.pyd', '.exe'}:
            return True
    except PATH_CONTRACT_EXCEPTIONS:
        result = False
    return result

normalize_scan_path = _canonical_normalize_scan_path

def runtime_library_score_cap(score: object, tags: object=None, path: object=None, strings_blob: object='', api_calls: object=None) -> object:
    """Cap known runtime/engine DLLs unless there is hard malicious proof.

    This prevents files such as libwinpthread-1.dll and libpython*.dll from
    becoming HIGH/MALICIOUS because they contain normal runtime capabilities:
    memory management, imports, interpreter strings, crypto/base64 routines,
    PE overlays/padding, or interop thunks.
    """
    score, score_reason = no_hook_finite_float(
        score,
        default=0.0,
        reason='runtime_score_rejected',
        non_finite_reason='runtime_score_non_finite',
    )
    evidence = [score_reason] if score_reason else []
    tagset = _norm_lower_set(normalize_tags(tags))
    text = _tag_validation_text(strings_blob)
    runtime = is_runtime_or_engine_library_path(path) or is_python_runtime_binary_path(path) or is_known_python_runtime_library_path(path, strings_blob) or bool(tagset & {'engine_runtime_library', 'runtime_library', 'python_runtime_binary', 'python_runtime_library', 'renpy_runtime_library', 'library_behavior_baseline:runtime_engine_binary', 'library_behavior_baseline:renpy_python_runtime_source'})
    if not runtime:
        return (score, evidence)
    hard_tags = {'yara_malware', 'known_bad_hash', 'malware_family', 'confirmed_embedded_pe_payload', 'decoded_pe_payload', 'embedded_pe_payload', 'mimikatz_credential_dump', 'lsass_access', 'credential_dump_attempt', 'amsi_scanbuffer_patch', 'etw_eventwrite_patch', 'write_process_memory', 'create_remote_thread', 'remote_thread_create', 'process_injection', 'encoded_powershell', 'powershell_exec', 'network_c2', 'remote_command_channel', 'backdoor_or_c2', 'network_exfiltration', 'token_exfiltration', 'http_upload'}
    calls = {call.strip().lower() for call in normalize_tags(api_calls) if call.strip()}
    injection_call_proof = {'writeprocessmemory', 'createremotethread'} <= calls or {'virtualallocex', 'writeprocessmemory', 'createremotethread'} <= calls
    hard_proof = bool(tagset & hard_tags) or injection_call_proof or _has_any_text(text, _RUNTIME_STRONG_ATTACK_CONTEXT)
    if hard_proof:
        evidence.append('runtime_cap_bypass_hard_proof')
        return (score, evidence)
    evidence.append('runtime_library_cap_score')
    return (min(score, 22.0), evidence)

def safe_extract_zip_member(z: object, member: object, tmp_dir: object) -> object:
    """
    Safely extract one ZIP member.
    """
    if type(member) is not zipfile.ZipInfo:
        raise ValueError('zip_member_metadata_rejected')
    root_text, root_reason = core_path_text(tmp_dir, field_name='zip_extract_root')
    if root_reason:
        raise ValueError(root_reason)
    name = no_hook_exact_owner_field(member, zipfile.ZipInfo, 'filename')
    if type(name) is not str:
        raise ValueError('zip_member_name_rejected')
    if Path(name).is_absolute() or '..' in Path(name).parts:
        raise ValueError(str.__add__('blocked unsafe zip member: ', name))
    root = str(Path(root_text).resolve())
    target = str((Path(root) / name).resolve())
    if not target.startswith(root + os.sep):
        raise ValueError(str.__add__('blocked zip-slip path: ', name))
    if zipfile.ZipInfo.is_dir(member):
        Path(target).mkdir(parents=True, exist_ok=True)
        return None
    Path(target).parent.mkdir(parents=True, exist_ok=True)
    with z.open(member, 'r') as src, Path(target).open('wb') as dst:
        shutil.copyfileobj(src, dst)
    return target
scan_path_text = _canonical_scan_path_text

def suppress_runtime_binary_capability_noise(tags: object, path: object=None, strings_blob: object='') -> object:
    """
    Demote CPython/Ren'Py runtime binary capability strings unless a real attack chain
    is present. PE/YARA/entropy/embedded-payload evidence is still retained; generic
    interpreter capabilities no longer score as malware by themselves.
    """
    if not (is_runtime_or_engine_library_path(path) or is_known_python_runtime_library_path(path, strings_blob)):
        return ordered_unique_tags(tags)
    text = _tag_validation_text(strings_blob)
    tagset = {str(t).lower() for t in tags or []}
    has_strong_attack = _has_any_text(text, _RUNTIME_STRONG_ATTACK_CONTEXT) or bool(tagset & {'yara_malware', 'known_bad_hash', 'malware_family', 'decoded_pe_payload', 'embedded_pe_payload', 'confirmed_embedded_pe_payload', 'powershell_exec', 'encoded_powershell', 'credential_dump_attempt', 'mimikatz_credential_dump', 'lsass_access'})
    if has_strong_attack:
        return ordered_unique_tags(tags)
    cleaned = []
    removed = False
    for t in tags or []:
        low = str(t).lower()
        if low in _RUNTIME_CAPABILITY_NOISE_TAGS:
            removed = True
            continue
        cleaned.append(t)
    if is_known_python_runtime_library_path(path, strings_blob):
        cleaned.append('python_runtime_library')
        cleaned.append('renpy_runtime_library')
    elif is_python_runtime_binary_path(path):
        cleaned.append('python_runtime_binary')
    else:
        cleaned.append('engine_runtime_library')
    if removed:
        cleaned.append('runtime_capability_noise_suppressed')
    return ordered_unique_tags(cleaned)
