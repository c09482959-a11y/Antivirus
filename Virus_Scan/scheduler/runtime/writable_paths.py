from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class ProcessQueueRuntimeDirs:
    temp_root: Path
    work_queue_root: Path
    run_dir: Path
    queue_dir: Path
    outputs_dir: Path


def create_process_queue_runtime_dirs(
    *,
    runtime_temp_dir: Callable[[], object],
    runtime_work_queue_dir: Callable[[], object] | None = None,
) -> ProcessQueueRuntimeDirs:
    temp_root = Path(runtime_temp_dir())
    temp_root.mkdir(parents=True, exist_ok=True)
    work_queue_root = Path(runtime_work_queue_dir()) if runtime_work_queue_dir is not None else temp_root / "work_queue"
    work_queue_root.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="umige_process_queue_", dir=str(work_queue_root)))
    queue_dir = run_dir / "queue"
    outputs_dir = run_dir / "outputs"
    outputs_dir.mkdir(parents=True, exist_ok=True)
    return ProcessQueueRuntimeDirs(temp_root=temp_root, work_queue_root=work_queue_root, run_dir=run_dir, queue_dir=queue_dir, outputs_dir=outputs_dir)
