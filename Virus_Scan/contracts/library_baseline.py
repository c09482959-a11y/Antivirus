"""Neutral library-baseline proof and profile contracts shared by path and profile models."""
from __future__ import annotations

import re
from pathlib import PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
from types import MappingProxyType
from typing import Callable, Iterable

from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.utils.text_match import has_any_text
from Virus_Scan.utils.text_validation import tag_validation_text

RUNTIME_LIBRARY_NAME_HINTS = frozenset({
    "librenpython.so", "librenpython.dylib", "renpython.dll", "python.dll", "pythonw.dll",
    "python.exe", "pythonw.exe", "unityplayer.dll", "gameassembly.dll", "mono.dll",
    "mono-2.0-bdwgc.dll", "libmono.so", "libunity.so", "libil2cpp.so", "nw.dll",
    "node.dll", "node.exe", "ffmpeg.dll", "libffmpeg.so", "chrome_elf.dll", "libcef.dll",
    "cefsharp.core.dll", "cefsharp.dll", "sdl2.dll", "openal32.dll", "vulkan-1.dll",
})
RUNTIME_LIBRARY_PREFIX_HINTS = (
    "libpython", "python3", "librenpython", "libwinpthread", "libgcc", "libstdc++", "libssp",
    "libgomp", "libmono", "libunity", "libil2cpp", "unityplayer", "gameassembly", "mono-",
    "node", "nw", "chrome_elf", "libcef", "cefsharp", "d3dcompiler", "sdl2", "openal",
    "avcodec", "avformat", "avutil", "libav", "libvpx", "libwebp", "libpng", "libjpeg",
)
RUNTIME_LIBRARY_PATH_HINTS = frozenset({
    "lib", "libs", "lib64", "renpy", "renpy.app", "py3-linux-x86_64", "py2-linux",
    "py3-windows", "py2-windows", "mono", "monobleedingedge", "managed", "plugins",
    "nwjs", "electron", "cef", "runtime", "jre", "bin",
})
RUNTIME_LIBRARY_EXTS = frozenset({".dll", ".so", ".dylib", ".pyd", ".node", ".exe"})
KNOWN_PYTHON_RUNTIME_LIBRARY_NAMES = frozenset({
    "bootstrap.py", "python.py", "core.py", "display.py", "event.py", "focus.py", "render.py",
})
KNOWN_PYTHON_RUNTIME_LIBRARY_PATH_HINTS = frozenset({
    "renpy", "renpy_base", "renpy.app", "renpy-", "renpy_runtime", "renpy_runtime_library",
})
RUNTIME_STRONG_ATTACK_CONTEXT = (
    "powershell -enc", "encodedcommand", "invoke-expression", "iex(", "cmd.exe /c",
    "wscript.shell", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "schtasks /create", "wmic process call create", "createprocessw(", "createprocessa(",
    "writeprocessmemory", "createremotethread", "ntcreatethreadex", "queueuserapc",
    "mimikatz", "sekurlsa", "minidumpwritedump", "lsass.exe", "amsiscanbuffer",
    "discord.com/api/webhooks", "api.telegram.org", "/gate.php", "/panel/", "reverse shell",
)

LIBRARY_BASELINE_HARD_PROOF_TAGS = frozenset({
    "yara_malware", "known_bad_hash", "malware_family",
    "confirmed_embedded_pe_payload", "decoded_pe_payload", "embedded_pe_payload",
    "image_payload_confirmed", "confirmed_stego_payload", "mimikatz_credential_dump",
    "lsass_access", "credential_dump_attempt", "amsi_scanbuffer_patch", "etw_eventwrite_patch",
"process_injection", "write_process_memory", "create_remote_thread",
    "remote_thread_create", "encoded_powershell", "powershell_exec", "c2_beacon",
    "backdoor_or_c2", "network_c2", "c2_or_remote_command",
})

LIBRARY_BASELINE_NORMAL_TAGS = MappingProxyType({
    "renpy_python_runtime_source": frozenset({
        "script_execution", "process_exec", "bytecode_exec", "bytecode_eval", "bytecode_subprocess",
        "code_execution",
        "pickle_deserialization_context", "marshal_load", "marshal_loads", "payload_decode_candidate",
        "obfuscated_script", "obfuscation_pack", "packed_or_obfuscated", "packer_marker",
        "persistent_save_data", "save_archive_access", "archive_dropper", "embedded_archive_payload",
        "dropper_behavior", "network_activity", "network_download", "network_download_execute",
        "process_launch_capability", "runtime_code_execution_capability",
        "runtime_eval_capability", "runtime_exec_capability", "runtime_process_capability",
        "runtime_serialization_capability", "runtime_import_capability", "stage_hit:archive dropper",
        "stage_hit:explicit packer marker", "staged_detection", "renpy_official_updater",
        "renpy_update_download_capability", "renpy_update_archive_apply_capability",
        "renpy_zsync_process_capability", "persistent_update_state", "renpy_updater_baseline_v1",
        "renpy_updater_dropper_chain_suppressed",
    }),
    "runtime_engine_binary": frozenset({
        "script_execution", "process_exec", "archive_dropper", "embedded_archive_payload",
        "dropper_behavior", "network_activity", "network_download", "network_download_execute",
        "dll_load", "dll_load_capability", "assembly_load", "reflection",
        "il_reflection", "base64", "payload_decode_candidate", "encoded_payload_candidate",
        "embedded_base64_payload", "persistence", "persistent_save_data", "save_archive_access",
        "packer_marker", "packed_or_obfuscated", "obfuscation_pack", "stage_hit:archive dropper",
        "stage_hit:explicit packer marker", "staged_detection",
    }),
})


def _safe_text(value: object) -> str:
    """Detach model-boundary text without caller-owned coercion hooks."""
    text = ""
    if value is None:
        text = ""
    elif type(value) is str:
        text = str.__str__(value)
    elif type(value) is bytes:
        text = bytes.decode(value, "utf-8", "replace")
    elif type(value) is bytearray:
        text = bytes(value).decode("utf-8", "replace")
    elif type(value) is memoryview:
        text = value.tobytes().decode("utf-8", "replace")
    elif type(value) in (bool, int, float):
        text = repr(value)
    return text


_STDLIB_PATH_TYPES = (PurePosixPath, PureWindowsPath, PosixPath, WindowsPath)

def _is_stdlib_pure_path(value: object) -> bool:
    return type(value) in _STDLIB_PATH_TYPES


def _safe_lower_text(value: object) -> str:
    return _safe_text(value).lower()


def _path_parts_status(path: object) -> tuple[tuple[str, ...], str]:
    if path is None:
        return ((), "missing_path")
    try:
        if isinstance(path, PurePath) and _is_stdlib_pure_path(path):
            return (tuple(part.lower() for part in path.parts), "")
        text = _safe_text(path)
        if text == "":
            return ((), "empty_path_text")
        return (tuple(part.lower() for part in PurePath(text).parts), "")
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
        return ((), "path_parts_unavailable")


def _path_parts(path: object) -> tuple[str, ...]:
    parts, _reason = _path_parts_status(path)
    return parts


def _lower_parts(path: object) -> frozenset[str]:
    return frozenset(_path_parts(path))


def _path_name_status(path: object) -> tuple[str, str]:
    if path is None:
        return ("", "missing_path")
    try:
        if isinstance(path, PurePath) and _is_stdlib_pure_path(path):
            return (path.name.lower(), "")
        text = _safe_text(path)
        if text == "":
            return ("", "empty_path_text")
        return (PurePath(text).name.lower(), "")
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
        return ("", "path_name_unavailable")


def _path_name(path: object) -> str:
    name, _reason = _path_name_status(path)
    return name


def _path_stem_suffix_parts_status(path: object) -> tuple[tuple[str, str, frozenset[str]] | None, str]:
    if path is None:
        return (None, "missing_path")
    try:
        p = path if _is_stdlib_pure_path(path) else PurePath(_safe_text(path))
        if not isinstance(p, PurePath) or str.__str__(p.name if type(p.name) is str else "") == "":
            return (None, "empty_path_name")
        parts = frozenset(part.replace("\\", "/").lower() for part in p.parts)
        return ((p.stem.lower(), p.suffix.lower(), parts), "")
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
        return (None, "path_stem_suffix_unavailable")


def _path_stem_suffix_parts(path: object) -> tuple[str, str, frozenset[str]] | None:
    parsed, _reason = _path_stem_suffix_parts_status(path)
    return parsed


def _detection_text(value: object) -> str:
    return _safe_lower_text(value)


def _has_any_runtime_text(text: str, needles: Iterable[str]) -> bool:
    return has_any_text(text, needles)


def _safe_tag_iter(tags: object) -> tuple[object, ...]:
    if tags is None:
        return ()
    if type(tags) is tuple:
        return tags
    if type(tags) is list:
        return tuple(list.__iter__(tags))
    if type(tags) is set:
        return tuple(set.__iter__(tags))
    if type(tags) is frozenset:
        return tuple(frozenset.__iter__(tags))
    return ()


def _safe_tagset(tags: object) -> frozenset[str]:
    return frozenset(text for tag in _safe_tag_iter(tags) if (text := _safe_lower_text(tag)))


def is_renpy_engine_runtime_source_path(path: object = None, strings_blob: object = "") -> bool:
    name = _path_name(path)
    parts = _lower_parts(path)
    text = _detection_text(strings_blob)
    if name == "core.py" and "renpy" in parts and "display" in parts:
        return True
    if name == "core.py" and "tom rothamel" in text and "pygame.event" in text and "class displayable" in text:
        return True
    return name in {"focus.py", "render.py", "layout.py", "screen.py", "im.py", "module.py"} and "renpy" in parts and "display" in parts


def is_known_python_runtime_library_path(path: object = None, strings_blob: object = "") -> bool:
    if path is None and _safe_text(strings_blob) == "":
        return False
    name = _path_name(path)
    parts = _lower_parts(path)
    if is_renpy_engine_runtime_source_path(path, strings_blob):
        return True
    if name not in KNOWN_PYTHON_RUNTIME_LIBRARY_NAMES:
        return False
    text = _detection_text(strings_blob)
    has_runtime_path_context = any("renpy" in part for part in parts) or bool(
        parts & KNOWN_PYTHON_RUNTIME_LIBRARY_PATH_HINTS
    )
    has_bootstrap_source_context = name == "bootstrap.py" and (
        ("tom rothamel" in text and "renpy.arguments.bootstrap" in text and "renpy.import_all" in text)
        or ("def bootstrap(renpy_base)" in text and "import renpy.config" in text)
    )
    has_python_source_context = name == "python.py" and (
        ("tom rothamel" in text and "def py_compile" in text and "def py_exec" in text and "store_dicts" in text)
        or ("class storedict" in text and "def py_exec_bytecode" in text and "marshal.loads" in text)
    )
    return has_runtime_path_context or has_bootstrap_source_context or has_python_source_context


def is_python_runtime_binary_path(path: object = None) -> bool:
    if path is None:
        return False
    name = _path_name(path)
    parsed = _path_stem_suffix_parts(path)
    if parsed is None:
        return False
    _stem, ext, parts = parsed
    is_supported_runtime_extension = ext in {".dll", ".exe", ".so", ".dylib", ""}
    has_python_runtime_name = name in {"python", "pythonw", "python.exe", "pythonw.exe"}
    has_versioned_python_library_name = re.match(
        r"^(?:lib)?python(?:\d+(?:\.\d+)*|\d{2,4})?(?:_d)?\.(?:dll|so|dylib|exe)$",
        name,
    )
    has_renpython_library_name = re.match(r"^librenpython(?:\d+(?:\.\d+)*)?\.(?:so|dylib|dll)$", name)
    has_runtime_directory_context = name in {"python", "pythonw"} and any(
        part.startswith(("py3", "python3")) for part in parts
    )
    return is_known_python_runtime_library_path(path) or (
        is_supported_runtime_extension
        and (
            has_python_runtime_name
            or bool(has_versioned_python_library_name)
            or bool(has_renpython_library_name)
            or has_runtime_directory_context
        )
    )


def is_runtime_or_engine_library_path(path: object = None) -> bool:
    if is_python_runtime_binary_path(path) or is_known_python_runtime_library_path(path):
        return True
    if path is None:
        return False
    name = _path_name(path)
    parsed = _path_stem_suffix_parts(path)
    if parsed is None:
        return False
    stem, ext, parts = parsed
    if ext not in RUNTIME_LIBRARY_EXTS:
        return False
    has_exact_runtime_name = name in RUNTIME_LIBRARY_NAME_HINTS
    has_prefixed_runtime_name = any(
        name.startswith(prefix) or stem.startswith(prefix) for prefix in RUNTIME_LIBRARY_PREFIX_HINTS
    )
    has_prefixed_runtime_context = has_prefixed_runtime_name and (
        bool(parts & RUNTIME_LIBRARY_PATH_HINTS) or ext in {".so", ".dylib", ".pyd", ".node"}
    )
    has_python_engine_name = name.startswith("python") and ext in {".dll", ".exe", ".so", ".dylib"}
    has_renpy_engine_name = ("renpy" in name or "renpython" in name) and ext in {
        ".dll",
        ".so",
        ".dylib",
        ".pyd",
        ".exe",
    }
    return has_exact_runtime_name or has_prefixed_runtime_context or has_python_engine_name or has_renpy_engine_name


def library_behavior_baseline_profile(path: object = None, strings_blob: object = "") -> dict[str, object] | None:
    """Return immutable normal-behavior baseline profile for known runtime/library files."""
    if is_known_python_runtime_library_path(path, strings_blob):
        return {
            "name": "renpy_python_runtime_source",
            "normal_tags": LIBRARY_BASELINE_NORMAL_TAGS["renpy_python_runtime_source"],
            "identity_tags": ("python_runtime_library", "renpy_runtime_library", "library_behavior_baseline:renpy_python_runtime_source"),
        }
    if is_runtime_or_engine_library_path(path):
        return {
            "name": "runtime_engine_binary",
            "normal_tags": LIBRARY_BASELINE_NORMAL_TAGS["runtime_engine_binary"],
            "identity_tags": ("engine_runtime_library", "library_behavior_baseline:runtime_engine_binary"),
        }
    return None


def library_baseline_hard_proof_status(
    tags: object = None,
    strings_blob: object = "",
    *,
    validation_text: Callable[[object], str] = tag_validation_text,
    logger: Callable[[str], None] = log_error,
) -> tuple[str, bool]:
    """Return explicit hard-proof status without importing scanner text internals."""
    tagset = _safe_tagset(tags)
    if tagset & LIBRARY_BASELINE_HARD_PROOF_TAGS:
        return ("tag_hard_proof", True)
    try:
        text = validation_text(_safe_text(strings_blob))
        has_proof = has_any_text(text, RUNTIME_STRONG_ATTACK_CONTEXT)
        return ("text_hard_proof" if has_proof else "no_hard_proof", bool(has_proof))
    except IO_CONFIGURATION_ERRORS as error:
        try:
            logger("library baseline hard-proof text validation failed: " + no_hook_type_name(error))
        except IO_CONFIGURATION_ERRORS:
            return ("probe_error", True)
        return ("probe_error", True)


def library_baseline_has_hard_proof(
    tags: object = None,
    strings_blob: object = "",
    *,
    validation_text: Callable[[object], str] = tag_validation_text,
    logger: Callable[[str], None] = log_error,
) -> bool:
    """Return True when baseline suppression must be bypassed for hard proof."""
    _status, has_hard_proof = library_baseline_hard_proof_status(
        tags, strings_blob, validation_text=validation_text, logger=logger
    )
    return bool(has_hard_proof)


__all__ = (
    "KNOWN_PYTHON_RUNTIME_LIBRARY_NAMES",
    "KNOWN_PYTHON_RUNTIME_LIBRARY_PATH_HINTS",
    "LIBRARY_BASELINE_HARD_PROOF_TAGS",
    "LIBRARY_BASELINE_NORMAL_TAGS",
    "RUNTIME_LIBRARY_EXTS",
    "RUNTIME_LIBRARY_NAME_HINTS",
    "RUNTIME_LIBRARY_PATH_HINTS",
    "RUNTIME_LIBRARY_PREFIX_HINTS",
    "RUNTIME_STRONG_ATTACK_CONTEXT",
    "is_known_python_runtime_library_path",
    "is_python_runtime_binary_path",
    "is_renpy_engine_runtime_source_path",
    "is_runtime_or_engine_library_path",
    "library_baseline_hard_proof_status",
    "library_baseline_has_hard_proof",
    "library_behavior_baseline_profile",
)
