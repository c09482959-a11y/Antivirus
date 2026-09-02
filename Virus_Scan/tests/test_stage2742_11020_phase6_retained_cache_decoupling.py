from __future__ import annotations

from types import SimpleNamespace

import Virus_Scan.reporting.result_schema as result_schema_module
from Virus_Scan.scheduler.orchestration.scheduler_serial_mode import (
    SchedulerSerialModeDependencies,
    SchedulerSerialModeRequest,
    run_scheduler_serial_mode,
)
from Virus_Scan.scheduler.queue.inmemory_result_completion_contracts import (
    InMemoryCompletedResultPublicationRequest,
)
from Virus_Scan.scheduler.queue.inmemory_result_completion_publication import (
    store_publish_and_maintain_completed_result,
)
from Virus_Scan.scheduler.queue.inmemory_result_completion_state import (
    InMemoryResultMessageParts,
)
from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache


def test_phase6_reporting_cache_writer_surface_is_physically_removed() -> None:
    assert "store_scan_cache_result" not in vars(result_schema_module)


def test_phase6_serial_retention_and_partial_publication_precede_derived_cache_write() -> None:
    results: dict[object, object] = {}
    events: list[str] = []

    def worker(path: str, _previous_stage: str, _strict: bool) -> tuple[str, dict[str, object]]:
        return path, {"classification": "benign_clean", "file": path}

    def retain(path: object, result: object) -> object:
        events.append("retain")
        return {"retained": path, "source": result}

    def partial(_force: bool) -> None:
        assert "sample.bin" in results
        events.append("partial")

    def cache_write(result: object) -> bool:
        assert "sample.bin" in results
        events.append("cache")
        return False

    run_scheduler_serial_mode(
        SchedulerSerialModeRequest(
            files=("sample.bin",),
            total_files=1,
            started_at=0.0,
            progress_every=1,
            throttle_sec=0.0,
            results=results,
        ),
        SchedulerSerialModeDependencies(
            worker=worker,
            prepare_result=retain,
            write_derived_cache=cache_write,
            write_partial=partial,
            bulk_scan_maintenance=lambda _count: None,
            log_bulk_progress=lambda *_args, **_kwargs: None,
            sleep=lambda _seconds: None,
        ),
    )

    assert events == ["retain", "partial", "cache"]


def test_phase6_inmemory_completion_stores_retained_result_before_derived_cache_write() -> None:
    results: dict[object, object] = {}
    recovery = SimpleNamespace(completed=0)
    events: list[str] = []
    parts = InMemoryResultMessageParts(
        job_id=1,
        path="sample.bin",
        result={"classification": "benign_clean", "file": "sample.bin"},
        pid=123,
        timestamp=1.0,
        attempt=0,
    )

    def retain(path: object, result: object) -> object:
        events.append("retain")
        return {"retained": path, "source": result}

    def cache_write(result: object) -> bool:
        assert results["sample.bin"]["retained"] == "sample.bin"
        assert recovery.completed == 1
        events.append("cache")
        return False

    request = InMemoryCompletedResultPublicationRequest(
        parts=parts,
        record={},
        results=results,
        recovery=recovery,
        container_root=None,
        routing_evidence_context=None,
        routing_evidence_attacher=lambda **kwargs: kwargs["result"],
        attach_result_evidence=lambda **kwargs: kwargs["result"],
        publish_partial_results=lambda _request: events.append("partial"),
        partial_output_path=None,
        partial_output_every=0,
        partial_writer=lambda *_args, **_kwargs: None,
        partial_checkpoint_cache=PartialCheckpointCache(),
        log_error=lambda _message: None,
        bulk_scan_maintenance=lambda _completed: None,
        log_bulk_progress=lambda *_args, **_kwargs: None,
        started_at=0.0,
        progress_every=1,
        wall_time=lambda: 1.0,
        job_records={},
        recoverable_exceptions=(Exception,),
        suppressed_recorder=lambda *_args, **_kwargs: None,
        result_retainer=retain,
        derived_cache_writer=cache_write,
    )

    store_publish_and_maintain_completed_result(request)

    assert events[0] == "retain"
    assert "cache" in events
