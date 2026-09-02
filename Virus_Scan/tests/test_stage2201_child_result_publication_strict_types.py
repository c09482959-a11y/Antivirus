"""Stage2201 strict typing closure for child-result publication boundaries."""
from __future__ import annotations

import ast
import json
from pathlib import Path

from Virus_Scan.scheduler.workers.child_result_publication import (
    ChildResultPersistRequest,
    WorkerOutputFinalizeRequest,
    WorkerOutputUpdateRequest,
    finalize_worker_output,
    persist_child_result,
    update_worker_output,
)

SOURCE = Path("Virus_Scan/scheduler/workers/child_result_publication.py")
CONTRACT_SOURCE = Path("Virus_Scan/scheduler/workers/child_result_publication_contracts.py")


class HostilePath:
    touched = 0

    def __fspath__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned __fspath__ executed")

    def __str__(self) -> str:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ executed")


class HostileStatus:
    touched = 0

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned __bool__ executed")


def _reporter(events: list[tuple[str, BaseException]]):
    def report(label: str, failure: BaseException) -> object:
        events.append((label, failure))
        return None

    return report


def test_stage2201_child_result_publication_exports_no_any_annotations() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    contract_source = CONTRACT_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert "Any" not in source
    assert "typing import Any" not in contract_source
    assert [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "Any"] == []
    assert "WorkerOutputBuffer" not in contract_source
    assert "ChildResultWriter" in contract_source


def test_stage2201_persist_child_result_rejects_hostile_status_before_bool(tmp_path: Path) -> None:
    HostileStatus.touched = 0
    events: list[tuple[str, BaseException]] = []

    ok = persist_child_result(
        ChildResultPersistRequest(
            queue_dir=tmp_path,
            claim_path=tmp_path / "claim.json",
            file_path=tmp_path / "sample.bin",
            result={"ok": True},
            context="stage2201",
            write_result=lambda *_args: HostileStatus(),
            report=_reporter(events),
            recoverable_exceptions=(RuntimeError, OSError, AssertionError),
        )
    )

    assert ok is False
    assert HostileStatus.touched == 0
    assert events
    assert events[0][0] == "stage2201.result_persist_result_rejected"


def test_stage2201_update_worker_output_records_no_hook_path_rejection() -> None:
    HostilePath.touched = 0
    child_results: dict[str, object] = {}
    events: list[tuple[str, BaseException]] = []

    ok = update_worker_output(
        WorkerOutputUpdateRequest(
            worker_output_path=HostilePath(),
            file_path="sample.bin",
            result={"ok": True},
            child_results=child_results,
            context="stage2201_output",
            report=_reporter(events),
        )
    )

    assert ok is False
    assert HostilePath.touched == 0
    assert events[0][0] == "stage2201_output.aggregate_write_rejected"
    evidence = child_results["__scheduler_worker_output_publication_failure__"]
    assert isinstance(evidence, dict)
    assert evidence["worker_output_publication_failed"] is True
    assert evidence["worker_output_publication_stage"] == "aggregate_write_rejected"


def test_stage2201_finalize_worker_output_uses_canonical_publication(tmp_path: Path) -> None:
    events: list[tuple[str, BaseException]] = []
    output_path = tmp_path / "worker-output.json"

    ok = finalize_worker_output(
        WorkerOutputFinalizeRequest(
            worker_output_path=output_path,
            child_results={"sample.bin": {"ok": True}},
            context="stage2201_final",
            report=_reporter(events),
        )
    )

    assert ok is True
    assert json.loads(output_path.read_text(encoding="utf-8")) == {"sample.bin": {"ok": True}}
    assert events == []
