"""Scanner-owned tag mapping for decoded pickle payload records."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scanners.contracts import scanner_contract_text
from Virus_Scan.scanners.payload_decode import decoded_payload_behavior_tags, safe_decode_payloads
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot

_PICKLE_POLICY = load_pickle_policy_snapshot()
EXEC_NEEDLES = _PICKLE_POLICY.decoded_payload_exec_needles
NETWORK_NEEDLES = _PICKLE_POLICY.decoded_payload_network_needles


def _pickle_payload_text(value: object, *, replacement: object = '') -> object:
    return scanner_contract_text(
        value,
        replacement=replacement,
        missing_reason="missing_pickle_payload_text",
        unsupported_reason="unsafe_pickle_payload_text_rejected",
    )


def _pickle_decoded_payload_tags(text: object, path: object = None) -> object:
    del path  # Explicitly unused contract parameters.
    payload_text = _pickle_payload_text(text)
    low = payload_text.lower()
    tags = []
    has_exec = any(item in low for item in EXEC_NEEDLES)
    has_network = any(item in low for item in NETWORK_NEEDLES)
    if has_exec:
        tags.extend(["process_exec", "script_execution", "payload_execution"])
        if "powershell" in low:
            tags.append("powershell_exec")
        if "cmd.exe" in low or "cmd /c" in low:
            tags.append("cmd_exec")
    if has_network:
        tags.extend(["network_activity", "network_download", "remote_payload_download"])
    if has_exec and has_network:
        tags.extend(["network_download", "remote_payload_download", "process_exec"])
    for rec in no_hook_sequence_items(safe_decode_payloads(payload_text, max_depth=5))[:16]:
        tags.extend(decoded_payload_behavior_tags(rec, tags))
    return tags


def _decoded_payload_is_official_renpy_runtime(dtags: object, decoded_text: object, path: object) -> object:
    dtags_l = {_pickle_payload_text(t).lower() for t in no_hook_sequence_items(dtags)}
    path_l = _pickle_payload_text(path).replace('\\', '/').lower()
    decoded_text_l = _pickle_payload_text(decoded_text).lower()
    official_tags = {'renpy_official_updater', 'renpy_updater_baseline_v1', 'renpy_updater_dropper_chain_suppressed'}
    return bool(dtags_l & official_tags) or (
        '/renpy/common/' in path_l
        and ('from store import renpy' in decoded_text_l or '@renpy.pure' in decoded_text_l or 'class ' in decoded_text_l)
    )


def _decoded_payload_exec_tags(dtags: object, decoded_text: object, path: object = None) -> object:
    dtags_l = {_pickle_payload_text(t).lower() for t in no_hook_sequence_items(dtags)}
    decoded_text_l = _pickle_payload_text(decoded_text).lower()
    explicit_exec_sink = any(x in decoded_text_l for x in (
        'os.system', 'subprocess', 'popen(', 'cmd.exe', 'powershell', 'createprocess',
        'shellexecute', 'startfile', 'eval(', 'exec(', 'compile(', 'runpy.run_path',
        'importlib.import_module',
    ))
    exec_like = bool(dtags_l & {
        'process_exec', 'network_download', 'powershell_exec', 'cmd_exec',
        'payload_execution', 'payload_decode_confirmed',
    }) or ('python_process_exec' in dtags_l and explicit_exec_sink)
    if exec_like and explicit_exec_sink and not _decoded_payload_is_official_renpy_runtime(dtags, decoded_text, path):
        return ['pickle_reduce_opcode', 'pickle_callable_reference', 'pickle_dangerous_global', 'renpy', 'renpy_script', 'script_execution', 'process_exec']
    return []


__all__ = ('_pickle_decoded_payload_tags', '_decoded_payload_exec_tags')
