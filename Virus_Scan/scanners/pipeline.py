from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_text
from Virus_Scan.contracts.env_config import int_env_status
from Virus_Scan.scanners.contracts import scanner_contract_join
import hashlib
import math
import re
import struct

PLR2004N126 = 126
PLR2004N32 = 32


def _ascii_visibility_ratio(buf: object) -> object:
    try:
        if not buf:
            return 0.0
        visible = sum((1 for b in buf if b in (9, 10, 13) or PLR2004N32 <= b <= PLR2004N126))
        return visible / float(len(buf))
    except SCAN_CONTENT_ERRORS:
        return -1.0

def _aw_float(value: object, default: object = 0.0) -> object:
    try:
        value = float(value)
        if not math.isfinite(value):
            return float(default)
        return value
    except SCAN_CONTENT_ERRORS:
        return float(default)

def _pipeline_text(value: object, *, replacement: object = '') -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='missing_scanner_pipeline_text',
        unsupported_reason='unsafe_scanner_pipeline_text_rejected',
    )
    return str.__str__(replacement) if reason and type(replacement) is str else text

def _ctx_any(text: object, needles: object) -> object:
    text = _pipeline_text(text).lower()
    for needle in no_hook_sequence_items(needles):
        needle_text = _pipeline_text(needle).lower()
        if needle_text and needle_text in text:
            return True
    return False

def _ctx_float(value: object, default: object = 0.0) -> object:
    try:
        value = float(value)
        if not math.isfinite(value):
            return float(default)
        return value
    except SCAN_CONTENT_ERRORS:
        return float(default)

def _ctx_re_status(pattern: object, text: object, flags: object = 0) -> object:
    """Return explicit scanner regex probe status without fail-open defaults."""
    try:
        return "match" if re.search(pattern, text, flags | re.IGNORECASE) is not None else "no_match"
    except (*SCAN_CONTENT_ERRORS, re.error):
        return "probe_error"


def _ctx_re(pattern: object, text: object, flags: object = 0) -> object:
    """Scanner context regex predicate; helper failures remain visible to callers."""
    status = _ctx_re_status(pattern, text, flags)
    if status == "probe_error":
        exception_message = "scanner context regex probe failed"
        raise ValueError(exception_message)
    return status == "match"


def _high_gate_calls(api_calls: object = None) -> object:
    calls = set()
    for call in no_hook_sequence_items(api_calls):
        text = _pipeline_text(call).strip().lower()
        if text:
            calls.add(text)
    return calls

def _jaccard(a: object, b: object) -> object:
    a = set(a or [])
    b = set(b or [])
    if not a and (not b):
        return 1.0
    return len(a & b) / max(1, len(a | b))

def _occurs_in_order(needed: object, events: object) -> object:
    pos = 0
    needed = list(needed or [])
    if not needed:
        return False
    for ev in events or []:
        if ev.get('tag') == needed[pos]:
            pos += 1
            if pos >= len(needed):
                return True
    return False

def _stable_entity_id(kind: object, value: object) -> object:
    kind_text = _pipeline_text(kind, replacement='entity') or 'entity'
    value_text = _pipeline_text(value, replacement='')
    raw = scanner_contract_join(kind_text, ':', value_text).encode('utf-8', errors='ignore')
    return scanner_contract_join(kind_text, ':', hashlib.sha256(raw).hexdigest()[:16])

def _umige_cstr_status(data: object, off: object, limit: object = 260) -> object:
    """Return explicit PE CString probe status without sentinel string fallbacks."""
    try:
        if off is None or off < 0 or off >= len(data):
            return ('missing_offset', '')
        end = data.find(b'\x00', off, min(len(data), off + limit))
        if end < 0:
            end = min(len(data), off + limit)
        return ('text', data[off:end].decode('latin1', errors='ignore'))
    except SCAN_CONTENT_ERRORS as exc:
        return ('decode_error', exc)


def _umige_cstr(data: object, off: object, limit: object = 260) -> object:
    status, value = _umige_cstr_status(data, off, limit)
    if status == 'decode_error':
        exception_message = 'scanner CString decode failed'
        raise ValueError(exception_message) from value if isinstance(value, BaseException) else TypeError(str(value))
    if type(value) is str:
        return value
    exception_message = 'scanner CString decode failed'
    raise ValueError(exception_message) from TypeError('scanner_cstring_not_text')

def _umige_retry_max_status(kind: object, *, env_reader: object = None) -> object:
    """Return explicit retry-limit parse status through the canonical env contract."""
    env_name = 'UMIGE_RAW_RETRY_MAX' if kind == 'raw' else 'UMIGE_FILE_RETRY_MAX'
    return int_env_status(env_name, 1, 0, None, env_reader=env_reader)


def _umige_retry_max(kind: object, *, env_reader: object = None) -> object:
    _status, value = _umige_retry_max_status(kind, env_reader=env_reader)
    return value

def _umige_rva_to_offset(rva: object, sections: object) -> object:
    try:
        for sec in sections:
            start = int(sec.get('virtual_address', 0))
            end = start + max(int(sec.get('virtual_size', 0)), int(sec.get('raw_size', 0)), 1)
            if start <= rva < end:
                return int(sec.get('raw_ptr', 0)) + (rva - start)
    except SCAN_CONTENT_ERRORS:
        return -1
    return None

def _umige_u16(data: object, off: object) -> object:
    return struct.unpack_from('<H', data, off)[0] if off + 2 <= len(data) else 0

def _umige_u32(data: object, off: object) -> object:
    return struct.unpack_from('<I', data, off)[0] if off + 4 <= len(data) else 0

def _umige_u64(data: object, off: object) -> object:
    return struct.unpack_from('<Q', data, off)[0] if off + 8 <= len(data) else 0

def compute_flow_coherence(flow: object) -> object:
    if not flow:
        return 0.0
    flow = [str(x) for x in flow]
    patterns = [['base64', 'reflection', 'process_exec'], ['network_download', 'process_exec'], ['network_download', 'assembly_load'], ['dll_load', 'memory_exec'], ['reflection', 'dynamic_code'], ['archive_extract', 'process_exec'], ['memory_allocate', 'memory_write', 'thread_execution']]
    score = 0.0
    for pattern in patterns:
        idx = 0
        for f in flow:
            if pattern[idx] in f:
                idx += 1
                if idx == len(pattern):
                    score += 0.5
                    break
    return min(score, 2.0)

def compute_similarity(tags_a: object, tags_b: object) -> object:
    set_a = set(tags_a)
    set_b = set(tags_b)
    if not set_a or not set_b:
        return 0.0
    return len(set_a & set_b) / len(set_a | set_b)

def increment_counter(counter_dict: object, key: object, amount: object = 1) -> object:
    """
    Safe simple counter increment.
    """
    key = str(key)
    counter_dict[key] = counter_dict.get(key, 0) + amount
    return counter_dict[key]
