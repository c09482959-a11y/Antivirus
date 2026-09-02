"""Explicit callable dependencies for standalone module/function use.

Stage 27 removes scanner/runtime callables from hidden registry injection.  These
small functions are safe to import without bootstrapping the runtime and are used
by modules that previously expected init_runtime to inject function symbols into
module globals.
"""
from __future__ import annotations
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.progress import report_progress
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.runtime.governance_inputs import runtime_bool, runtime_int

from Virus_Scan.runtime.config_state import get_deep_scan_mode
from Virus_Scan.runtime.graph_state import ensure_graph_node_owned
from Virus_Scan.contracts.path_identity import get_scan_extension as contract_get_scan_extension
from Virus_Scan.utils.tagging import ordered_unique_tags as unique_tag_order

from dataclasses import dataclass, field
from pathlib import Path, PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
from threading import RLock
from typing import Callable, Dict, Optional

_STDLIB_PATH_TYPES = (Path, PosixPath, WindowsPath, PurePosixPath, PureWindowsPath)


def _dependency_field_name(field_name: object, *, default: str = "scan_dependency_input") -> str:
    text, reason = no_hook_text(
        field_name,
        missing_reason="scan_dependency_field_missing",
        unsupported_reason="scan_dependency_field_rejected",
    )
    if reason or text == "":
        return default
    return text


def _dependency_text(
    value: object,
    field_name: str,
    *,
    default: str | None = None,
    allow_blank: bool = False,
) -> str:
    field_text = _dependency_field_name(field_name)
    text, reason = no_hook_text(
        value,
        missing_reason=field_text + "_missing",
        unsupported_reason=field_text + "_rejected",
    )
    if reason:
        if default is not None:
            return default
        raise ValueError(reason)
    if text == "" and not allow_blank:
        if default is not None:
            return default
        raise ValueError(field_text + "_blank")
    return text


def _dependency_path(value: object) -> Path:
    if type(value) in _STDLIB_PATH_TYPES:
        return Path(PurePath.as_posix(value))
    return Path(_dependency_text(value, "scan_dependency_path"))


def read_file_bytes(path: str | Path, max_size: Optional[int] = 5_000_000) -> bytes:
    """Bounded binary read used by scanners outside full runtime bootstrap."""
    p = _dependency_path(path)
    with p.open("rb") as fh:
        if max_size is None:
            return fh.read()
        limit, issues = runtime_int(
            max_size, field_name="scan_dependency_max_size", default=5_000_000
        )
        if issues:
            raise ValueError("scan_dependency_max_size_rejected")
        return fh.read(limit)


def safe_read_text(path: str | Path, max_size: Optional[int] = 5_000_000) -> str:
    data = read_file_bytes(path, max_size=max_size)
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(enc, errors="ignore")
        except RECOVERABLE_RUNTIME_ERRORS:
            continue
    return data.decode("utf-8", errors="ignore")



def report_scan_stage_progress(stage: str = "scan", inc: int = 1, bytes_delta: int = 0) -> Dict[str, object]:
    """Report a scanner sub-stage progress checkpoint through the runtime owner."""
    return report_progress(stage, inc, bytes_delta)



@dataclass
class ScanDependencyRegistry:
    """Lifecycle-owned callable ports for cross-layer scanner dependencies.

    This object is the explicit owner for the few scanner services whose concrete
    implementations would otherwise create runtime/scanner import cycles.  It is
    not a shared publication surface: unsupported providers fail fast and
    callers use canonical local implementations where ownership is already known.
    """

    scan_strings_provider: Callable[..., object] | None = None
    string_event_provider: Callable[..., object] | None = None
    raw_string_stage_provider: Callable[..., object] | None = None
    engine_context_detector: Callable[..., object] | None = None
    intrastage_provider: dict[str, Callable[..., object]] = field(default_factory=dict)
    lock: RLock = field(default_factory=RLock)

    def set_single(self, name: str, provider: Callable[..., object]) -> Callable[..., object]:
        name = _dependency_text(name, "scan_dependency_provider_name")
        if not callable(provider):
            raise TypeError(name + " provider must be callable")
        with self.lock:
            if name == "scan_strings_provider":
                self.scan_strings_provider = provider
            elif name == "string_event_provider":
                self.string_event_provider = provider
            elif name == "raw_string_stage_provider":
                self.raw_string_stage_provider = provider
            elif name == "engine_context_detector":
                self.engine_context_detector = provider
            else:
                raise KeyError("unknown scan dependency provider: " + name)
        return provider

    def get_single(self, name: str) -> Callable[..., object] | None:
        name = _dependency_text(name, "scan_dependency_provider_name")
        with self.lock:
            if name == "scan_strings_provider":
                provider = self.scan_strings_provider
            elif name == "string_event_provider":
                provider = self.string_event_provider
            elif name == "raw_string_stage_provider":
                provider = self.raw_string_stage_provider
            elif name == "engine_context_detector":
                provider = self.engine_context_detector
            else:
                raise KeyError("unknown scan dependency provider: " + name)
        return provider if callable(provider) else None

    def update_group(self, group_name: str, providers: dict[str, Callable[..., object]]) -> dict[str, Callable[..., object]]:
        group_name = _dependency_text(
            group_name, "scan_dependency_provider_group"
        )
        items = no_hook_mapping_items(providers)
        if items is None:
            raise TypeError("scan_dependency_providers_mapping_rejected")
        valid: dict[str, Callable[..., object]] = {}
        for key, provider in items:
            if not callable(provider):
                continue
            name = _dependency_text(
                key, "scan_dependency_group_provider_name"
            )
            valid[name] = provider
        with self.lock:
            if group_name == "intrastage_provider":
                self.intrastage_provider = dict(valid)
                return dict(self.intrastage_provider)
            raise KeyError("unknown scan dependency provider group: " + group_name)

    def get_group_provider(self, group_name: str, provider_name: str) -> Callable[..., object] | None:
        group_name = _dependency_text(
            group_name, "scan_dependency_provider_group"
        )
        provider_name = _dependency_text(
            provider_name, "scan_dependency_group_provider_name"
        )
        with self.lock:
            if group_name == "intrastage_provider":
                provider = self.intrastage_provider.get(provider_name)
            else:
                raise KeyError("unknown scan dependency provider group: " + group_name)
        return provider if callable(provider) else None


_SCAN_DEPENDENCIES = ScanDependencyRegistry()


def _resolve_scan_dependency_registry(registry: ScanDependencyRegistry | None = None) -> ScanDependencyRegistry:
    """Return an explicit dependency registry without mutating global runtime state."""
    return registry if registry is not None else _SCAN_DEPENDENCIES


def ensure_graph_node(node: object) -> object:
    """Write graph nodes through the canonical runtime graph owner."""
    return ensure_graph_node_owned(node)

def _deep_scan_mode() -> str:
    return _dependency_text(
        get_deep_scan_mode("auto"),
        "deep_scan_mode",
        default="auto",
    ).lower()


def deep_scan_fast_assets_enabled() -> bool:
    return _deep_scan_mode() in {"fast", "balanced", "default", "auto", "adaptive", "escalate"}


def deep_scan_thorough_enabled() -> bool:
    return _deep_scan_mode() in {"thorough", "deep", "exhaustive"}


def deep_scan_auto_enabled() -> bool:
    return _deep_scan_mode() in {"auto", "adaptive", "escalate"}


def has_any_tag(tags: object, *needles: str) -> bool:
    rows: tuple[object, ...]
    if tags is None:
        rows = ()
    elif type(tags) in (tuple, list, set, frozenset):
        rows = no_hook_sequence_items(tags)
    else:
        raise TypeError("scan_dependency_tags_sequence_rejected")
    safe_tags: set[str] = {
        _dependency_text(tag, "scan_dependency_tag")
        for tag in rows
    }
    safe_needles = tuple(
        _dependency_text(needle, "scan_dependency_needle")
        for needle in needles
    )
    return any(needle in safe_tags for needle in safe_needles)


def get_scan_extension(path: object) -> str:
    """Return the canonical scan extension from the path identity contract."""
    return contract_get_scan_extension(path)

def ordered_unique_tags(*args: object, **kwargs: object) -> object:
    """Return canonical ordered unique tags."""
    if args:
        return unique_tag_order(args[0])
    return unique_tag_order(kwargs.get('tags'))


def register_scan_strings_provider(provider: object) -> object:
    return _SCAN_DEPENDENCIES.set_single("scan_strings_provider", provider)


_STRING_SCAN_RULES: tuple[tuple[str, str], ...] = (
    ("powershell", "powershell_exec"),
    ("encodedcommand", "encoded_powershell"),
    (" -enc ", "encoded_powershell"),
    ("http://", "url_present"),
    ("https://", "url_present"),
    ("downloadstring", "network_download"),
    ("downloadfile", "network_download"),
    ("invoke-webrequest", "network_download"),
    ("certutil", "certutil_exec"),
    ("bitsadmin", "bitsadmin_exec"),
    ("mshta", "mshta_exec"),
    ("rundll32", "rundll32_exec"),
    ("regsvr32", "regsvr32_exec"),
    ("writeprocessmemory", "memory_write"),
    ("virtualalloc", "memory_allocate"),
    ("createremotethread", "thread_execution"),
)


def _scan_string_content(data: object) -> list[str]:
    """Return deterministic string-evidence tags before scanner bootstrap."""
    text = _dependency_text(
        data, "scan_dependency_string_content", allow_blank=True
    )
    lowered = " " + text.lower() + " "
    tags = [tag for needle, tag in _STRING_SCAN_RULES if needle in lowered]
    if {"network_download", "url_present"} <= set(tags):
        tags.append("download_observable")
    if {"powershell_exec", "encoded_powershell"} <= set(tags):
        tags.append("encoded_script_execution")
    return list(unique_tag_order(tags))


def scan_strings(*args: object, registry: ScanDependencyRegistry | None = None, **kwargs: object) -> object:
    """Call the lifecycle-owned string scanner service or local string evidence scanner."""
    provider = _resolve_scan_dependency_registry(registry).get_single("scan_strings_provider")
    if callable(provider):
        return provider(*args, **kwargs)
    data = args[0] if args else kwargs.get("data", "")
    return _scan_string_content(data)


def register_string_event_provider(provider: object) -> object:
    return _SCAN_DEPENDENCIES.set_single("string_event_provider", provider)


def iter_ordered_string_events(*args: object, registry: ScanDependencyRegistry | None = None, **kwargs: object) -> object:
    provider = _resolve_scan_dependency_registry(registry).get_single("string_event_provider")
    if callable(provider):
        return provider(*args, **kwargs)
    data = args[0] if args else kwargs.get("data", "")
    text = _dependency_text(
        data, "scan_dependency_string_event_content", allow_blank=True
    )
    low = text.lower()
    events: list[tuple[int, dict[str, object]]] = []
    for needle, tag in _STRING_SCAN_RULES:
        idx = low.find(needle.strip())
        if idx >= 0:
            events.append((idx, {"tag": tag, "raw": text[idx:idx + len(needle.strip())]}))
    return list.__iter__(sorted(events, key=lambda item: item[0]))


def register_raw_string_stage_provider(provider: object) -> object:
    return _SCAN_DEPENDENCIES.set_single("raw_string_stage_provider", provider)


def raw_stage_scan_strings(*args: object, registry: ScanDependencyRegistry | None = None, **kwargs: object) -> object:
    provider = _resolve_scan_dependency_registry(registry).get_single("raw_string_stage_provider")
    if callable(provider):
        return provider(*args, **kwargs)
    data = args[0] if args else kwargs.get("data", "")
    return _scan_string_content(data)


def register_engine_context_detector(provider: object) -> object:
    return _SCAN_DEPENDENCIES.set_single("engine_context_detector", provider)


def detect_target_engine_context(scan_root: object, max_files: object=120, *, registry: ScanDependencyRegistry | None = None) -> object:
    provider = _resolve_scan_dependency_registry(registry).get_single("engine_context_detector")
    if callable(provider):
        return provider(scan_root, max_files=max_files)
    return {"unity": 0.0, "renpy": 0.0, "rpgm": 0.0, "unknown": 1.0}


def register_intrastage_provider(**providers: object) -> object:
    return _SCAN_DEPENDENCIES.update_group("intrastage_provider", providers)


def intrastage_enabled(*, registry: ScanDependencyRegistry | None = None) -> object:
    fn = _resolve_scan_dependency_registry(registry).get_group_provider("intrastage_provider", "intrastage_enabled")
    if not callable(fn):
        return False
    enabled, issues = runtime_bool(
        fn(), field_name="intrastage_enabled", default=False
    )
    if issues:
        raise ValueError("intrastage_enabled_result_rejected")
    return enabled


def stage_parallel_workers(*, registry: ScanDependencyRegistry | None = None) -> object:
    fn = _resolve_scan_dependency_registry(registry).get_group_provider("intrastage_provider", "stage_parallel_workers")
    if not callable(fn):
        return 1
    workers, issues = runtime_int(
        fn(), field_name="stage_parallel_workers", default=1
    )
    if issues or workers < 1:
        raise ValueError("stage_parallel_workers_result_rejected")
    return workers


def run_raw_task_queue(*args: object, registry: ScanDependencyRegistry | None = None, **kwargs: object) -> object:
    fn = _resolve_scan_dependency_registry(registry).get_group_provider("intrastage_provider", "run_raw_task_queue")
    if not callable(fn):
        exception_message = "raw task queue provider is not registered"
        raise RuntimeError(exception_message)
    return fn(*args, **kwargs)


def append_intrastage_string_tasks(*args: object, registry: ScanDependencyRegistry | None = None, **kwargs: object) -> object:
    fn = _resolve_scan_dependency_registry(registry).get_group_provider("intrastage_provider", "append_intrastage_string_tasks")
    if not callable(fn):
        exception_message = "intrastage string task provider is not registered"
        raise RuntimeError(exception_message)
    return fn(*args, **kwargs)

