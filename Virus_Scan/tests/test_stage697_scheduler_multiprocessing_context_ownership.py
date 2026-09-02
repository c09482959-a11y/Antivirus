from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path
import subprocess
import sys

_RESOURCE_TRACKER_SUBPROCESS_TIMEOUT_SECONDS = 90

from Virus_Scan.scheduler.runtime.multiprocessing_context import (
    choose_scheduler_start_method,
    get_scheduler_multiprocessing_context,
    shutdown_scheduler_multiprocessing_context_runtime,
)



def test_scheduler_multiprocessing_context_avoids_fork_when_forkserver_available():
    assert (
        choose_scheduler_start_method(
            platform_name="posix",
            available_start_methods=("fork", "spawn", "forkserver"),
        )
        == "forkserver"
    )


def test_scheduler_multiprocessing_context_uses_spawn_when_only_spawn_is_safe():
    assert (
        choose_scheduler_start_method(
            platform_name="nt",
            available_start_methods=("spawn",),
        )
        == "spawn"
    )


def test_scheduler_multiprocessing_context_rejects_fork_preference():
    assert (
        choose_scheduler_start_method(
            preferred="fork",
            platform_name="posix",
            available_start_methods=("fork", "spawn"),
        )
        == "spawn"
    )


def test_execution_longlived_queue_uses_runtime_owned_context():
    source = read_python_file(Path("Virus_Scan/scheduler/orchestration/inmemory_parent_runtime_setup.py"))
    assert "import multiprocessing" not in source
    assert "get_context" not in source
    assert "get_scheduler_multiprocessing_context" in source


def test_scheduler_multiprocessing_context_provider_returns_nonfork_context():
    ctx = get_scheduler_multiprocessing_context()
    assert ctx.get_start_method() != "fork"


def test_stage2030_scheduler_context_provider_uses_policy_selected_nonfork_method():
    ctx = get_scheduler_multiprocessing_context()
    assert ctx.get_start_method() == choose_scheduler_start_method()
    assert ctx.get_start_method() != "fork"


def test_stage1643_scheduler_context_resource_tracker_shutdown_is_explicit_in_subprocess():
    code = r"""
import ctypes
from Virus_Scan.scheduler.runtime.multiprocessing_context import (
    get_scheduler_multiprocessing_context,
    shutdown_scheduler_multiprocessing_context_runtime,
)
ctx = get_scheduler_multiprocessing_context()
ctx.Array(ctypes.c_int, 2, lock=False)
ctx.BoundedSemaphore(1)
stopped = shutdown_scheduler_multiprocessing_context_runtime()
assert "resource_tracker" in stopped, stopped
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path.cwd(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=_RESOURCE_TRACKER_SUBPROCESS_TIMEOUT_SECONDS,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_stage2042_scheduler_multiprocessing_context_has_no_atexit_shutdown_hook():
    source = read_python_file(Path("Virus_Scan/scheduler/runtime/multiprocessing_context.py"))
    assert "atexit.register" not in source
    assert "import atexit" not in source
    assert "shutdown_scheduler_multiprocessing_context_runtime" in source


def test_stage2042_scheduler_multiprocessing_shutdown_returns_without_helper_pid():
    stopped = shutdown_scheduler_multiprocessing_context_runtime()
    assert "forkserver_no_helper_pid" in stopped or "forkserver" in stopped
    assert "resource_tracker_no_helper_pid" in stopped or "resource_tracker" in stopped
