"""Binary scanner behavior predicates and low-level signal helpers."""

from __future__ import annotations


from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scanners.binary_entropy_helpers import shannon_entropy_bytes as _shannon_entropy_bytes
from Virus_Scan.scanners.binary_text_signals import binary_regex_match, binary_ascii_visibility_ratio, binary_text_has_any
from Virus_Scan.scanners.binary_behavior_policy import BINARY_C2_TASKING_TERMS, BINARY_COMMAND_EXECUTION_TERMS


def _has_archive_dropper_behavior(text: object) -> object:
    archive_ctx = binary_text_has_any(text, ['zipfile', 'tarfile', 'gzip', 'extractall', 'extract(', '7z.exe', 'rar.exe', 'cabinet', 'pk\\x03\\x04'])
    payload_ctx = binary_text_has_any(text, ['.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.scr', '.msi', 'writeallbytes', '%temp%', 'appdata', 'startup', 'currentversion\\run'])
    write_ctx = binary_text_has_any(text, ['extractall', 'extract(', 'writeallbytes', 'createfile', 'copyfile', 'movefile', 'unpack', 'decompress'])
    persist_or_exec = _has_command_exec_behavior(text) or binary_text_has_any(text, ['schtasks', 'currentversion\\run', 'startup', 'service create', 'runonce'])
    return bool(archive_ctx and payload_ctx and write_ctx and persist_or_exec)


def _has_command_exec_behavior(text: object) -> object:
    return binary_text_has_any(text, BINARY_COMMAND_EXECUTION_TERMS) or binary_text_has_any(text, ['powershell', 'cmd.exe', 'subprocess', 'popen(', 'os.system', 'process.start', 'createprocess', 'child_process', 'exec(', 'eval('])


def _has_c2_behavior(text: object) -> object:
    has_url = bool(binary_regex_match(r'\b(?:https?|ftp|ws|wss)://', text) or binary_regex_match(r'\b(?:socket\.connect|tcpclient|recv\(|send\()', text))
    tasking = binary_text_has_any(text, BINARY_C2_TASKING_TERMS) or (binary_text_has_any(text, ['recv(', 'send(']) and binary_text_has_any(text, ['command', 'cmd', 'task', 'shell', 'beacon', 'implant']))
    execution = _has_command_exec_behavior(text) or binary_text_has_any(text, BINARY_COMMAND_EXECUTION_TERMS)
    return bool(has_url and tasking and execution)


def _predicate_text(value: object, *, unsupported_reason: str) -> tuple[str, str]:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_binary_predicate_text",
        unsupported_reason=unsupported_reason,
    )
    if reason:
        return "", reason
    return str.lower(text), ""


def _predicate_sequence(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    if type(value) in (tuple, list):
        return tuple(value)
    return ()


def _predicate_options(value: object) -> tuple[str, ...]:
    raw_values = tuple(value) if type(value) in (tuple, list, set, frozenset) else (value,)
    options: list[str] = []
    for raw in raw_values:
        text, reason = _predicate_text(
            raw,
            unsupported_reason="unsafe_binary_predicate_needle_rejected",
        )
        normalized = str.strip(text)
        if not reason and normalized:
            options.append(normalized)
    return tuple(options)


def _predicate_event_text(value: object) -> str:
    if type(value) is dict:
        pieces: list[str] = []
        for key in ("tag", "name", "api", "event", "call", "value", "text"):
            raw = dict.get(value, key)
            text, reason = _predicate_text(
                raw,
                unsupported_reason="unsafe_binary_predicate_event_field_rejected",
            )
            normalized = str.strip(text)
            if not reason and normalized:
                pieces.append(normalized)
        return " ".join(pieces)
    text, reason = _predicate_text(
        value,
        unsupported_reason="unsafe_binary_predicate_event_rejected",
    )
    return str.strip(text) if not reason else ""


def _ordered_contains_subsequence(stream: object, *needles: object) -> object:
    """Return True when needles appear in order in an owned ordered stream."""
    items = _predicate_sequence(stream)
    if len(items) == 0 or len(needles) == 0:
        return False
    needle_groups = tuple(_predicate_options(wanted) for wanted in needles)
    if any(len(group) == 0 for group in needle_groups):
        return False
    pos = 0
    for item in items:
        text = _predicate_event_text(item)
        if not text:
            continue
        if any(option in text for option in needle_groups[pos]):
            pos += 1
            if pos >= len(needle_groups):
                return True
    return False


def _binary_delayed_execution_score(events: object) -> object:
    event_items = _predicate_sequence(events)
    tags = tuple(_predicate_event_text(ev) for ev in event_items)
    delay_markers = {'sleep', 'timeout', 'delayed_execution', 'long_sleep', 'anti_sandbox_sleep'}
    exec_markers = {'powershell_exec', 'cmd_exec', 'process_injection', 'thread_execution', 'dll_load'}
    for i, t in enumerate(tags):
        if t in delay_markers and any((x in exec_markers for x in tags[i + 1:i + 8])):
            return (4.0, ['temporal_delayed_execution'])
    return (0.0, [])


def _binary_blob_bytes(data: object) -> bytes:
    if type(data) is bytes:
        return data
    if type(data) is bytearray:
        return bytes(data)
    if type(data) is memoryview:
        return data.tobytes()
    raise TypeError("unsafe_binary_blob_rejected")


def _xor_blob_signal(data: object) -> object:
    """Weak XOR/encoded blob heuristic using entropy and non-text ratio."""
    blob = _binary_blob_bytes(data)
    if len(blob) < 512:
        return False
    sample = blob[:min(len(blob), 65536)]
    ent = _shannon_entropy_bytes(sample)
    visible = binary_ascii_visibility_ratio(sample)
    if visible < 0.0:
        return False
    return ent >= 7.15 and visible <= 0.45

__all__ = (
    "_binary_delayed_execution_score",
    "_has_archive_dropper_behavior",
    "_has_c2_behavior",
    "_has_command_exec_behavior",
    "_ordered_contains_subsequence",
    "_xor_blob_signal",
)
