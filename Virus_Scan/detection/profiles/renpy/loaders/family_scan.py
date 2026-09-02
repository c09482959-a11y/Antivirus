"""Ren'Py loader-specific family tag ownership."""

from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.detection.contracts.pickle_opcode import detect_python_pickle_opcode_exec
from Virus_Scan.detection.contracts.string_predicates import context_regex
from Virus_Scan.utils.tagging import ordered_unique_tags


def _renpy_loader_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='renpy_loader_text_missing',
        unsupported_reason='renpy_loader_text_rejected',
    )
    if reason:
        return ''
    return text


def _renpy_loader_bool(value: object) -> object:
    if value is None:
        return False
    if type(value) in (bool, int, float, str, bytes, bytearray, tuple, list, set, frozenset, dict):
        return bool(value)
    return False



def _renpy_loader_contains(text: str, items: object) -> bool:
    return any(item.lower() in text for item in items)


def _resolve_renpy_pickle_contexts(
    text: str,
    pickle_opcode_context: object,
    pickle_exec_context: object,
) -> tuple[object, object]:
    if pickle_opcode_context is None:
        direct_opcode = _renpy_loader_contains(text, (
            "cos\nsystem", "subprocess\npopen", "builtins\neval", "builtins\nexec", "posix\nsystem",
            "nt\nsystem", "__reduce__", "__reduce_ex__", "stack_global", "opcode: global", "opcode: reduce", "pickletools",
        ))
        regex_opcode = context_regex("\b(?:proto|global|reduce)\b", text) and _renpy_loader_contains(text, ("pickle", "pickletools", "opcode"))
        executable_opcode = _renpy_loader_contains(text, ("os.system(", "subprocess", "popen(", "eval(", "exec(", "cmd.exe", "powershell", "import os"))
        pickle_opcode_context = direct_opcode or (regex_opcode and executable_opcode)
    if pickle_exec_context is None:
        pickle_exec_context = _renpy_loader_contains(text, ("os.system(", "os system", "subprocess", "popen(", "eval(", "exec(", "cmd.exe", "powershell", "import os"))
    return pickle_opcode_context, pickle_exec_context


def _append_python_pickle_opcode_tags(text: str, ext: str, tags: list[object]) -> None:
    if ext in {".py", ".pyc", ".pyo"}:
        tags.extend(detect_python_pickle_opcode_exec(text, ext))



def _append_renpy_archive_pickle_tags(
    text: str,
    ext: str,
    name: str,
    contexts: tuple[object, object],
    tags: list[object],
) -> None:
    if ext not in {".rpyc", ".rpyb", ".rpa"} and "renpy" not in name:
        return
    pickle_opcode_context, pickle_exec_context = contexts
    if _renpy_loader_bool(pickle_opcode_context) and _renpy_loader_bool(pickle_exec_context):
        tags.extend(("renpy", "renpy_script", "pickle_callable_reference", "pickle_dangerous_global", "script_execution", "process_exec"))
    archive_context = ext == ".rpa" or "rpa-3.0" in text
    if archive_context and _renpy_loader_contains(text, ("pickle", "opcode", "global", "reduce", "exec", "eval", "subprocess", "os.system")):
        tags.extend(("pickle_file_load_context", "save_archive_access", "pickle_callable_reference", "script_execution"))


def renpy_loader_family_tags(
    blob: object,
    *,
    path: object = None,
    data: object = None,
    pickle_opcode_context: object = None,
    pickle_exec_context: object = None,
) -> object:
    """Return tags for Ren'Py loader and archive pickle execution evidence."""
    del data
    tags: list[object] = []
    text = _renpy_loader_text(blob).lower()
    path_text = _renpy_loader_text(path)
    ext = get_scan_extension(path_text) if path_text else ""
    name = Path(path_text).name.lower() if path_text else ""
    opcode_context, exec_context = _resolve_renpy_pickle_contexts(
        text,
        pickle_opcode_context,
        pickle_exec_context,
    )
    _append_python_pickle_opcode_tags(text, ext, tags)
    _append_renpy_archive_pickle_tags(text, ext, name, (opcode_context, exec_context), tags)
    return ordered_unique_tags(tags)


__all__ = ('renpy_loader_family_tags',)
