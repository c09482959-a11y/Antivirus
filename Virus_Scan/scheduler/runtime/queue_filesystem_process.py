"""Scheduler runtime process/filesystem policy helpers."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

from Virus_Scan.runtime.api import temp_dir as _runtime_temp_dir
from Virus_Scan.runtime.api import work_queue_dir as _runtime_work_queue_dir
from Virus_Scan.scheduler.runtime.queue_filesystem_common import QUEUE_FILESYSTEM_EXCEPTIONS


def scheduler_runtime_temp_dir() -> Path:
    try:
        return _runtime_temp_dir()
    except QUEUE_FILESYSTEM_EXCEPTIONS:
        root = Path.cwd().resolve()
        temp_root = root / "Temp"
        temp_root.mkdir(parents=True, exist_ok=True)
        return temp_root


def scheduler_runtime_work_queue_dir() -> Path:
    try:
        return _runtime_work_queue_dir()
    except QUEUE_FILESYSTEM_EXCEPTIONS:
        work_root = scheduler_runtime_temp_dir() / "work_queue"
        work_root.mkdir(parents=True, exist_ok=True)
        return work_root


def scheduler_subprocess_stdin() -> object:
    return subprocess.DEVNULL


def scheduler_windows_creationflags(*, worker: bool = False, helper: bool = False) -> int:
    if os.name != "nt" or not (worker or helper):
        return 0
    flags = 0
    process_group = subprocess.__dict__.get("CREATE_NEW_PROCESS_GROUP", 0)
    no_window = subprocess.__dict__.get("CREATE_NO_WINDOW", 0)
    if type(process_group) is int and type(process_group) is not bool:
        flags |= process_group
    if type(no_window) is int and type(no_window) is not bool:
        flags |= no_window
    return flags
