"""Detection-owned pickle opcode graph analysis contracts."""
from __future__ import annotations

import pickle
import pickletools
import re
from typing import Iterable

from Virus_Scan.contracts.path_identity import get_scan_extension, path_identity
from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_text
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.contracts.pickle_opcode import RENPY_PICKLE_EXTENSIONS
from Virus_Scan.detection.evidence.failure_evidence import recoverable_failure_evidence
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.detection.registries.chain_registry import CHAIN_CONCLUSION_TAGS

PLR2004N3 = 3

PICKLE_DECODE_MAX_FILE_BYTES = 5 * 1024 * 1024
PICKLE_DECODE_MAX_OFFSETS = 128
PICKLE_DECODE_MAX_DECODED_BYTES = 262144
DANGEROUS_GLOBAL_TERMS = frozenset({
    "os.system", "posix.system", "nt.system", "subprocess.popen", "subprocess.call",
    "subprocess.run", "builtins.eval", "builtins.exec", "eval", "exec", "compile",
    "runpy.run_path", "importlib.import_module", "win32process.createprocess",
})
SUSPICIOUS_GLOBAL_TERMS = frozenset({
    "pickle.loads", "marshal.loads", "base64.b64decode", "zlib.decompress", "gzip.decompress",
    "socket.create_connection", "requests.get", "requests.post", "urllib.request.urlopen",
})


def _append_pickle_failure(summary: dict[str, object], *, stage_name: str, error: BaseException, source: str) -> None:
    summary["errors"] = int(summary.get("errors", 0)) + 1
    summary["degraded"] = True
    failures = summary.setdefault("failure_evidence", [])
    failures.append(recoverable_failure_evidence(
        stage_name=stage_name,
        error=error,
        error_source=source,
        affected_context="pickle_opcode_graph",
    ))


def _arg_to_text(arg: object) -> str:
    if type(arg) is bytes:
        return bytes(arg).decode("latin1", errors="ignore")
    if type(arg) is bytearray:
        return bytes(arg).decode("latin1", errors="ignore")
    if type(arg) is tuple:
        return " ".join(_arg_to_text(item) for item in arg)
    text, reason = no_hook_text(arg, missing_reason="missing_pickle_arg_text", unsupported_reason="unsafe_pickle_arg_text_rejected")
    return text if reason == "" else ""


def _canonical_global(*parts: object) -> str:
    cleaned = []
    for part in parts:
        text = _arg_to_text(part).strip().replace("\n", ".")
        if text:
            cleaned.append(text)
    text = ".".join(cleaned).replace("..", ".").strip(".").lower()
    return {
        "cposix.system": "posix.system",
        "cos.system": "os.system",
        "cnt.system": "nt.system",
    }.get(text, text)


def pickle_dangerous_global(global_name: object) -> bool:
    text, reason = no_hook_text(global_name, missing_reason="missing_pickle_global_text", unsupported_reason="unsafe_pickle_global_text_rejected")
    low = text.lower() if reason == "" else ""
    return any(term in low for term in DANGEROUS_GLOBAL_TERMS)


def pickle_suspicious_global(global_name: object) -> bool:
    text, reason = no_hook_text(global_name, missing_reason="missing_pickle_global_text", unsupported_reason="unsafe_pickle_global_text_rejected")
    low = text.lower() if reason == "" else ""
    return pickle_dangerous_global(low) or any(term in low for term in SUSPICIOUS_GLOBAL_TERMS)


def pickle_offsets(blob: bytes) -> list[int]:
    offsets = [0]
    for match in re.finditer(b"\\x80[\\x02\\x03\\x04\\x05]", blob):
        if match.start() not in offsets:
            offsets.append(match.start())
        if len(offsets) >= PICKLE_DECODE_MAX_OFFSETS:
            break
    return offsets


def path_is_renpy_pickle(path: object = None) -> bool:
    try:
        low = path_identity(path).raw.replace("\\", "/").lower() if path is not None else ""
        ext = get_scan_extension(path) if path is not None else ""
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        low = ""
        ext = ""
    return ext in RENPY_PICKLE_EXTENSIONS or "renpy" in low or "/game/" in low


def _record_global(summary: dict[str, object], stack: list[object], value: str) -> str:
    if value:
        stack.append(value)
        summary["globals"].append(value)
        if pickle_dangerous_global(value):
            summary["dangerous_globals"].append(value)
    return value


def _opcode_name(op: object) -> str:
    if type(op) is not pickletools.OpcodeInfo:
        return ""
    name = op.name
    return str.__str__(name).upper() if type(name) is str else ""


def _pickle_position(value: object) -> int:
    metric, reason = no_hook_exact_nonnegative_int(value, default=0, allow_exact_text=False, reason="unsafe_pickle_position_rejected")
    return metric if reason == "" else 0


def _pickle_blob(data: object) -> bytes | None:
    if data is None:
        return b""
    if type(data) is bytes:
        return bytes(data)[:PICKLE_DECODE_MAX_FILE_BYTES]
    if type(data) is bytearray:
        return bytes(data)[:PICKLE_DECODE_MAX_FILE_BYTES]
    if type(data) is memoryview:
        return bytes(data)[:PICKLE_DECODE_MAX_FILE_BYTES]
    return None


def analyze_pickle_opcode_graph(data: bytes | bytearray | None, max_ops: int = 4096) -> dict[str, object]:
    summary: dict[str, object] = {
        "valid_pickle": False, "offsets": [], "opcodes": [], "globals": [],
        "dangerous_globals": [], "reduce_chains": [], "trigger_windows": [],
        "literal_fragments": [], "has_reduce": False, "has_stack_global": False,
        "has_build": False, "has_exec_chain": False, "errors": 0,
        "degraded": False, "failure_evidence": [],
    }
    blob = _pickle_blob(data)
    if blob is None:
        _append_pickle_failure(summary, stage_name="pickle_opcode_input_bytes", error=TypeError("unsupported pickle opcode input"), source="pickle opcode input type")
        return summary
    if not blob:
        return summary
    for offset in pickle_offsets(blob):
        stack: list[object] = []
        memo: dict[int, object] = {}
        last_callable = ""
        history: list[dict[str, object]] = []
        try:
            for count, (op, arg, pos) in enumerate(pickletools.genops(blob[offset:]), start=1):
                if count > max_ops:
                    break
                name = _opcode_name(op)
                if not name:
                    _append_pickle_failure(summary, stage_name="pickle_opcode_name_unavailable", error=TypeError("unsupported pickle opcode record"), source="pickletools opcode record")
                    continue
                op_position = _pickle_position(pos)
                summary["valid_pickle"] = True
                summary["offsets"].append(offset)
                summary["opcodes"].append(name)
                history = ([*history, {'opcode': name, 'arg': _arg_to_text(arg)[:180], 'stream_offset': offset, 'op_position': op_position}])[-12:]
                if name in {"BINBYTES", "SHORT_BINBYTES", "BINBYTES8", "BYTEARRAY8", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8", "UNICODE", "STRING"}:
                    text = _arg_to_text(arg)
                    if text:
                        stack.append(text)
                        if PLR2004N3 <= len(text) <= PICKLE_DECODE_MAX_DECODED_BYTES:
                            summary["literal_fragments"].append(text)
                    continue
                if name in {"BINPUT", "LONG_BINPUT", "PUT"}:
                    if stack:
                        try:
                            memo[_pickle_position(arg)] = stack[-1]
                        except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
                            _append_pickle_failure(summary, stage_name="pickle_opcode_memo_store", error=error, source="pickle memo store")
                    continue
                if name in {"BINGET", "LONG_BINGET", "GET"}:
                    try:
                        stack.append(memo.get(_pickle_position(arg), ""))
                    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
                        _append_pickle_failure(summary, stage_name="pickle_opcode_memo_lookup", error=error, source="pickle memo lookup")
                    continue
                if name == "GLOBAL":
                    last_callable = _record_global(summary, stack, _canonical_global(arg))
                    continue
                if name == "STACK_GLOBAL":
                    summary["has_stack_global"] = True
                    name_part = stack.pop() if stack else ""
                    module_part = stack.pop() if stack else ""
                    first = _canonical_global(module_part, name_part)
                    second = _canonical_global(name_part, module_part)
                    last_callable = _record_global(summary, stack, first if pickle_dangerous_global(first) or pickle_suspicious_global(first) else second)
                    continue
                if name in {"REDUCE", "BUILD", "OBJ", "NEWOBJ", "NEWOBJ_EX", "INST"}:
                    summary["has_reduce"] = summary["has_reduce"] or name == "REDUCE"
                    summary["has_build"] = summary["has_build"] or name == "BUILD"
                    for candidate in [last_callable, *dict.get(summary, "dangerous_globals", [])[-4:]]:
                        if pickle_dangerous_global(candidate):
                            callable_text, reason = no_hook_text(candidate, missing_reason="missing_pickle_callable_text", unsupported_reason="unsafe_pickle_callable_text_rejected")
                            if reason != "":
                                continue
                            chain = {"opcode": name, "callable": callable_text.lower(), "stream_offset": offset, "op_position": op_position}
                            summary["reduce_chains"].append(chain)
                            summary["trigger_windows"].append({**chain, "ops": list(history[-8:])})
                            summary["has_exec_chain"] = True
        except (ValueError, EOFError, pickle.UnpicklingError, StopIteration, TypeError, IndexError) as error:
            _append_pickle_failure(summary, stage_name="pickle_opcode_stream_decode", error=error, source="pickletools.genops")
    for key in ("offsets", "opcodes", "globals", "dangerous_globals", "literal_fragments"):
        summary[key] = list(dict.fromkeys(dict.get(summary, key, [])))
    return summary


def unify_pickle_detection_tags(tags: Iterable[object], path: object = None) -> list[str]:
    """Return atomic pickle observations; chain identity is never inferred here."""
    source_tags = () if type(tags) not in (tuple, list, set, frozenset) else tuple(tags)
    out: list[str] = []
    for tag in source_tags:
        text, reason = no_hook_text(
            tag,
            missing_reason="missing_pickle_tag_text",
            unsupported_reason="unsafe_pickle_tag_text_rejected",
        )
        clean = text.strip() if reason == "" else ""
        if clean and clean not in CHAIN_CONCLUSION_TAGS:
            out.append(clean)
    low = {tag.lower() for tag in out}
    if low & {
        "pickle_external_executable_reference",
        "pickle_external_script_reference",
        "pickle_external_file_reference",
    }:
        out.append("pickle_file_load_context")
    return ordered_unique_tags(out)


__all__ = (
    "PICKLE_DECODE_MAX_DECODED_BYTES",
    "PICKLE_DECODE_MAX_FILE_BYTES",
    "PICKLE_DECODE_MAX_OFFSETS",
    "analyze_pickle_opcode_graph",
    "path_is_renpy_pickle",
    "pickle_dangerous_global",
    "pickle_offsets",
    "unify_pickle_detection_tags",
)
