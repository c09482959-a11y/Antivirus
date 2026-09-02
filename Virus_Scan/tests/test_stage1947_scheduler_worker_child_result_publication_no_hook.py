from pathlib import Path

from Virus_Scan.scheduler.workers.child_result_publication import (
    ChildResultPersistRequest,
    WorkerOutputFinalizeRequest,
    WorkerOutputUpdateRequest,
    finalize_worker_output,
    persist_child_result,
    update_worker_output,
)
from Virus_Scan.scheduler.workers.publication_status import safe_publication_context


SCHEDULER_ROOT = Path(__file__).resolve().parents[1] / "scheduler"


class HostileContext:
    touched = 0

    @classmethod
    def reset(cls):
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("context str hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("context repr hook executed")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("context format hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("context bool hook executed")


class HostileStatus:
    touched = 0

    @classmethod
    def reset(cls):
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("status bool hook executed")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("status str hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("status repr hook executed")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("status format hook executed")


def test_stage1947_child_publication_source_has_no_fallback_fstring_or_default_false_returns():
    child_source = (SCHEDULER_ROOT / "workers" / "child_result_publication.py").read_text(encoding="utf-8")
    status_source = (SCHEDULER_ROOT / "workers" / "publication_status.py").read_text(encoding="utf-8")

    assert "fallback=" not in child_source
    assert "fallback" not in status_source
    assert "report(f" not in child_source
    assert "f\"{safe_context}" not in child_source
    assert "return False" not in child_source


def test_stage1947_publication_context_rejects_hostile_context_without_hooks():
    HostileContext.reset()

    safe_context = safe_publication_context(HostileContext(), replacement_text="worker_result")

    assert safe_context == "worker_result"
    assert HostileContext.touched == 0


def test_stage1947_child_result_failure_paths_emit_evidence_without_context_or_status_hooks(tmp_path):
    HostileContext.reset()
    HostileStatus.reset()
    calls = []
    child_results = {}
    blocked_parent = tmp_path / "blocked-parent"
    blocked_parent.write_text("not a directory", encoding="utf-8")

    assert persist_child_result(
        ChildResultPersistRequest(
            queue_dir=tmp_path,
            claim_path=tmp_path / "claim.json",
            file_path=tmp_path / "file.bin",
            result={"scan_integrity": {}},
            context=HostileContext(),
            write_result=lambda *_args: HostileStatus(),
            report=lambda where, exc: calls.append((where, type(exc).__name__, exc.args)),
        )
    ) is False
    assert update_worker_output(
        WorkerOutputUpdateRequest(
            worker_output_path=str(blocked_parent / "worker.json"),
            file_path=str(tmp_path / "file.bin"),
            result={"scan_integrity": {}},
            child_results=child_results,
            context=HostileContext(),
            report=lambda where, exc: calls.append((where, type(exc).__name__, exc.args)),
        )
    ) is False
    assert finalize_worker_output(
        WorkerOutputFinalizeRequest(
            worker_output_path=str(blocked_parent / "worker-final.json"),
            child_results=child_results,
            context=HostileContext(),
            report=lambda where, exc: calls.append((where, type(exc).__name__, exc.args)),
        )
    ) is False

    assert HostileContext.touched == 0
    assert HostileStatus.touched == 0
    assert calls[0] == (
        "worker_result.result_persist_result_rejected",
        "RuntimeError",
        ("scheduler_worker_publication_status_rejected",),
    )
    assert calls[1] == (
        "worker_output.aggregate_write_rejected",
        "RuntimeError",
        ("aggregate worker output publication rejected",),
    )
    assert calls[2] == (
        "worker_output_final.aggregate_finalize_failed",
        "RuntimeError",
        ("aggregate worker output publication rejected",),
    )
    assert len(calls) == 3
    assert "__scheduler_worker_output_publication_failure__" in child_results
