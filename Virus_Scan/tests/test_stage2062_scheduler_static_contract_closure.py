from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.internal.immutable_output_support import FrozenSchedulerMapping
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.queue.raw_queue_duplicates import duplicate_live_guard
from Virus_Scan.scheduler.workers.cleanup_no_hook import call_cleanup_method
from Virus_Scan.scheduler.workers.process_control_no_hook import call_process_method


def _source(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_stage2062_scheduler_suppression_repairs_removed_type_ignores() -> None:
    repaired_files = (
        "Virus_Scan/scheduler/orchestration/inmemory_timeout_config_job_evidence.py",
        "Virus_Scan/scheduler/workers/cleanup_no_hook.py",
        "Virus_Scan/scheduler/workers/process_control_no_hook.py",
    )
    for path in repaired_files:
        assert "# type: ignore" not in _source(path)


def test_stage2062_immutable_mapping_contract_returns_frozen_scheduler_mapping() -> None:
    snapshot = immutable_mapping({"status": "typed", "count": 1})
    assert type(snapshot) is FrozenSchedulerMapping
    assert snapshot["status"] == "typed"
    assert snapshot["count"] == 1


class _CleanupProcess:
    def wait(self, timeout: int | None = None) -> tuple[str, int | None]:
        return ("waited", timeout)


class _ControlledProcess:
    def poll(self) -> int:
        return 7


def test_stage2062_process_method_boundaries_call_unbound_methods_without_suppressions() -> None:
    cleanup_result, cleanup_reason = call_cleanup_method(_CleanupProcess(), "wait", timeout=3)
    assert cleanup_reason == ""
    assert cleanup_result == ("waited", 3)

    process_result, process_reason = call_process_method(_ControlledProcess(), "poll")
    assert process_reason == ""
    assert process_result == 7


def test_stage2062_phase_ledger_uses_canonical_integrity_pipeline_wrapper() -> None:
    source = _source("Virus_Scan/scheduler/queue/phase_ledger.py")
    assert "from Virus_Scan.scheduler.queue.integrity_pipeline import queue_integrity_verify_and_repair" in source
    assert "from Virus_Scan.scheduler.queue.integrity import verify_and_repair_queue_integrity" not in source


def test_stage2062_duplicate_guard_exception_path_has_initialized_identity(tmp_path) -> None:
    reports: list[dict[str, object]] = []

    def _raising_identity(_job: object, _claim_name: object) -> str:
        raise RuntimeError("identity failed")

    def _report(_where: str, _exc: BaseException, *, fatal: bool, extra: dict[str, object]) -> None:
        reports.append(extra)

    allowed = duplicate_live_guard(
        tmp_path,
        tmp_path / "active" / "claim.json",
        {},
        job_identity=_raising_identity,
        job_dirs=lambda queue_dir: (queue_dir / "pending", queue_dir / "active", queue_dir / "done", queue_dir / "failed"),
        safe_listdir=lambda _path: (),
        is_job_json_name=lambda _name: True,
        read_json=lambda _path: {},
        merge_claim_meta=lambda _path, job=None: job or {},
        quarantine_job=lambda _path, *, reason, job, identity: True,
        report=_report,
    )

    assert allowed is False
    assert reports
    assert reports[0]["identity"] == ""
    assert "claim_path" in reports[0]
