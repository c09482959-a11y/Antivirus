"""Worker-owned process cleanup and final wait helpers."""

import os as _os
from collections.abc import Callable


from Virus_Scan.scheduler.workers.process_control_no_hook import (
    safe_process_control_text,
)
from Virus_Scan.scheduler.workers.process_termination import (
    WorkerProcessHandleTerminationResult,
    terminate_process_queue_worker_handle,
)

_GET_PROCESS_GROUP_ID: Callable[[int], int] | None = getattr(_os, "getpgid", None)
_KILL_PROCESS_GROUP: Callable[[int, int], None] | None = getattr(_os, "killpg", None)
_PROCESS_GROUPS_UNSUPPORTED = "process groups are unsupported on this platform"



class _WorkerOS:
    @property
    def name(self) -> str:
        return _os.name

    def fspath(self, path: object) -> str:
        return _os.fspath(path)

    def getpgid(self, pid: int) -> int:
        get_process_group_id = _GET_PROCESS_GROUP_ID
        if not callable(get_process_group_id):
            raise OSError(_PROCESS_GROUPS_UNSUPPORTED)
        return int(get_process_group_id(pid))

    def killpg(self, pgid: int, sig: int) -> None:
        kill_process_group = _KILL_PROCESS_GROUP
        if not callable(kill_process_group):
            raise OSError(_PROCESS_GROUPS_UNSUPPORTED)
        kill_process_group(pgid, sig)


os = _WorkerOS()


from Virus_Scan.scheduler.workers.cleanup_exit_result import WorkerExitWaitResult
from Virus_Scan.scheduler.workers.cleanup_wait_steps import (
    WorkerExitWaitStepContext,
    wait_for_process_queue_worker_exit_steps,
)


def terminate_process_queue_worker(
    proc: object,
    *,
    action: object,
    worker_idx: object,
    report_failure: object,
) -> WorkerProcessHandleTerminationResult:
    """Terminate or kill a process-queue worker and return immutable worker evidence."""
    action_name, _action_reason = safe_process_control_text(
        action,
        replacement_text="terminate",
        reason="process_queue_idle_cleanup_action_rejected",
    )
    result = terminate_process_queue_worker_handle(
        worker_idx=worker_idx,
        proc=proc,
        action=action_name,
        reason="process_queue_idle_cleanup",
    )
    if result.requested and not result.completed and result.error:
        try:
            report_failure(
                "worker_" + result.action + "_failed",
                RuntimeError(result.error),
            )
        except (OSError, RuntimeError, TypeError, ValueError) as report_exc:
            _ = report_exc
    return result


def wait_for_process_queue_worker_exit(
    proc: object,
    context: WorkerExitWaitStepContext,
) -> WorkerExitWaitResult:
    """Wait for a worker and return immutable evidence for final cleanup."""
    return wait_for_process_queue_worker_exit_steps(
        proc,
        context,
    )
