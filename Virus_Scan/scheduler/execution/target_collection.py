from pathlib import Path
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
# Real module split from v27c for scheduler/collect.py.
# Functionality lives here; shared state is synchronized through this subsystem state module.
import os

# Stage 27 explicit bootstrap-safe dependencies; scanners no longer rely on
# init_runtime injecting these callables into module globals.
from Virus_Scan.routing.extensions import should_scan_path
from Virus_Scan.runtime.api import get_init_value
from Virus_Scan.runtime.api import log_error
from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.internal.exception_projection import scheduler_error_detail
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_filesystem_path,
    scheduler_text,
)


def _excluded_dirs_snapshot(value: object) -> object:
    if value is None:
        return frozenset({'.git', '__pycache__'})
    items = no_hook_sequence_items(value)
    if not items and type(value) not in {list, tuple, set, frozenset}:
        return frozenset({'.git', '__pycache__'})
    excluded = []
    for item in items:
        text, reason = scheduler_text(
            item,
            unsupported_reason="scheduler_excluded_directory_rejected",
        )
        if reason == "" and text:
            excluded.append(text)
    return frozenset(excluded or {'.git', '__pycache__'})


DEFAULT_EXCLUDED_DIRS = _excluded_dirs_snapshot(get_init_value('DEFAULT_EXCLUDED_DIRS'))


def _required_filesystem_path(value: object, *, field_name: object) -> object:
    path, reason = scheduler_filesystem_path(value)
    if reason or (type(path) is str and path == ""):
        field_text = str.__str__(field_name) if type(field_name) is str else "scheduler_path"
        reason_text = str.__str__(reason) if type(reason) is str and reason else "scheduler_path_missing"
        raise ValueError(field_text + ":" + reason_text)
    return path

def collect_target_files(root: object, file_list_path: object=None) -> object:
    """Collect scan targets deterministically while honoring exclusions.

    file_list_path is used by the process scheduler: the parent process does one
    deterministic walk, balances paths across shard manifests, and child
    processes scan only the paths assigned to them. This avoids each child
    walking the whole tree and enables true multi-core execution for CPU-heavy
    Python detectors that cannot fully scale under threads because of the GIL.
    """
    root_path = _required_filesystem_path(root, field_name="scheduler_target_root")
    if file_list_path is not None:
        list_path = _required_filesystem_path(
            file_list_path,
            field_name="scheduler_target_file_list",
        )
        out = []
        try:
            with Path(list_path).open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    item = line.rstrip("\n")
                    if item and Path(item).is_file() and should_scan_path(item, scan_root=root_path):
                        out.append(item)
        except RECOVERABLE_RUNTIME_ERRORS as e:
            log_error(
                "file list load failed: "
                + scheduler_error_detail(e, max_length=500)
            )
            raise
        return sorted(
            dict.fromkeys(out),
            key=lambda item: str.__str__(item).replace("\\", "/").casefold(),
        )

    if Path(root_path).is_file():
        return [root_path] if should_scan_path(
            root_path,
            scan_root=str(Path(root_path).resolve().parent),
        ) else []
    all_files = []
    for r, dirs, files in os.walk(root_path):
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in DEFAULT_EXCLUDED_DIRS
            and should_scan_path(str(Path(r, d)), scan_root=root_path)
        )
        for name in sorted(files):
            path = str(Path(r, name))
            if should_scan_path(path, scan_root=root_path):
                all_files.append(path)
    return sorted(
        all_files,
        key=lambda item: str.__str__(item).replace("\\", "/").casefold(),
    )



