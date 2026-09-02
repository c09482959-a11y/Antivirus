from pathlib import Path

from Virus_Scan.scheduler.workers.claim_heartbeat import (
    WorkerClaimHeartbeatHandle,
    start_worker_claim_heartbeat,
    stop_worker_claim_heartbeat,
)


SCHEDULER_ROOT = Path(__file__).resolve().parents[1] / "scheduler"


class HostileScalar:
    touched = 0

    @classmethod
    def reset(cls):
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("repr hook executed")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("format hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("bool hook executed")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("float hook executed")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("int hook executed")


class HostileHandle:
    touched = 0

    def __getattribute__(self, name):
        if name in {"stop_event", "thread"}:
            type(self).touched += 1
            raise RuntimeError("descriptor hook executed")
        return object.__getattribute__(self, name)


class WrongHandle(WorkerClaimHeartbeatHandle):
    pass


def test_stage1948_claim_heartbeat_source_has_no_fallback_or_literal_false_returns():
    source = (SCHEDULER_ROOT / "workers" / "claim_heartbeat.py").read_text(encoding="utf-8")

    assert "fallback=" not in source
    assert "default_interval" not in source
    assert "default=2.0" not in source
    assert "return False" not in source


def test_stage1948_claim_heartbeat_rejects_hostile_inputs_without_hooks():
    HostileScalar.reset()
    seen = []

    handle = start_worker_claim_heartbeat(
        "claim.json",
        job=HostileScalar(),
        worker_id=HostileScalar(),
        interval_sec=HostileScalar(),
        update_callback=lambda _path, *, job, worker_id: seen.append((job, worker_id)) or True,
    )

    assert handle.worker_id == "worker"
    assert handle.interval_sec == 5.0
    assert seen[0][1] == "worker"
    assert stop_worker_claim_heartbeat(handle, timeout_sec=HostileScalar()) is True
    assert HostileScalar.touched == 0


def test_stage1948_stop_claim_heartbeat_rejects_invalid_handle_without_descriptor_hooks():
    HostileScalar.reset()
    HostileHandle.touched = 0

    assert stop_worker_claim_heartbeat(HostileHandle(), timeout_sec=HostileScalar()) is False

    assert HostileHandle.touched == 0
    assert HostileScalar.touched == 0


def test_stage1948_worker_cleanup_source_has_no_legacy_fallback_or_fstring_markers():
    cleanup = (SCHEDULER_ROOT / "workers" / "cleanup.py").read_text(encoding="utf-8")
    cleanup_no_hook = (SCHEDULER_ROOT / "workers" / "cleanup_no_hook.py").read_text(encoding="utf-8")
    process_control = (SCHEDULER_ROOT / "workers" / "process_control_no_hook.py").read_text(encoding="utf-8")

    for source in (cleanup, cleanup_no_hook, process_control):
        assert "fallback=" not in source
    assert "getpgid = getattr" not in cleanup
    assert "killpg = getattr" not in cleanup
    assert "report_failure(f" not in cleanup
    assert "failure_markers.append(f" not in cleanup
    assert "marker = f\"queue_worker_final_" not in cleanup
    assert "return None, safe_process_control_exception_name" not in cleanup_no_hook


def test_stage1948_process_control_helpers_and_termination_calls_are_not_fallback_routes():
    process_control = (SCHEDULER_ROOT / "workers" / "process_control_no_hook.py").read_text(encoding="utf-8")
    process_termination = (SCHEDULER_ROOT / "workers" / "process_termination.py").read_text(encoding="utf-8")

    assert "def safe_process_control_int(value: Any, *, fallback" not in process_control
    assert "return scheduler_int(value" not in process_control
    assert "def safe_process_control_text(value: Any, *, fallback" not in process_control
    assert "fallback=" not in process_termination
    assert "return None, safe_process_control_exception_name" not in process_control
