from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_stage2636_scheduler_helper_cleanup_does_not_run_unrelated_finalizers() -> None:
    code = r"""
from multiprocessing import util as mp_util
from Virus_Scan.scheduler.runtime.multiprocessing_context import (
    shutdown_scheduler_multiprocessing_context_runtime,
)

called = []
finalizer = mp_util.Finalize(
    None,
    lambda: called.append("unrelated"),
    exitpriority=0,
)
shutdown_scheduler_multiprocessing_context_runtime()
assert called == [], called
finalizer.cancel()
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path.cwd(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_stage2636_scheduler_helper_cleanup_source_has_no_global_finalizer_runner() -> None:
    source = Path(
        "Virus_Scan/scheduler/runtime/multiprocessing_helper_cleanup.py"
    ).read_text(encoding="utf-8")

    assert "_run_finalizers" not in source
    assert "multiprocessing import util" not in source
