from __future__ import annotations

import pickle
from pathlib import Path

from Virus_Scan.contracts.yara_hits import unavailable_yara_scan_result
from Virus_Scan.routing.context_evidence_context import RoutingEvidenceContext
from Virus_Scan.routing.extension_outcome import RouteScanOutcome
from Virus_Scan.scheduler.evidence.inmemory_result_timeout import attach_inmemory_result_evidence
from Virus_Scan.scheduler.evidence.inmemory_route_identity import (
    INMEMORY_ROUTE_IDENTITY_FIELD,
    attach_inmemory_route_identity,
    consume_inmemory_route_identity,
)
from Virus_Scan.scheduler.orchestration.scheduler_serial_mode import (
    SchedulerSerialModeDependencies,
    SchedulerSerialModeRequest,
    run_scheduler_serial_mode,
)
from Virus_Scan.scheduler.workers.inmemory_file_scan_support import (
    complete_inmemory_analysis_result,
)


class _Budget:
    def as_evidence(self) -> dict[str, object]:
        return {"worker_state": "test"}


def _router_identity() -> dict[str, object]:
    return {
        "ext": ".imgblob",
        "magic_type": "unknown_binary_blob",
        "magic_stage": "binary",
        "tags": (
            "ext_imgblob",
            "magic_binary_blob",
            "magic_type_unknown_binary_blob",
        ),
        "extension_mismatch": False,
    }


def test_full_inmemory_analysis_reuses_exact_route_identity_and_context(tmp_path: Path) -> None:
    target = tmp_path / "sample.imgblob"
    target.write_bytes(b"administrator SMB documentation with an incidental MZ token")
    context = RoutingEvidenceContext.build(tmp_path)
    identity = _router_identity()
    observed: dict[str, object] = {}

    def analyze(path: object, **kwargs: object) -> dict[str, object]:
        observed["path"] = path
        observed.update(kwargs)
        return {
            "file": str(path),
            "path": str(path),
            "node": str(path),
            "score": 0.0,
            "class": "benign_clean",
            "classification": "benign_clean",
            "tags": ["filetype_binary"],
            "explanation": {"classification": "benign_clean"},
        }

    completed_path, result = complete_inmemory_analysis_result(
        path=target,
        tags=("filetype_binary",),
        tag_evidence=("filetype_binary",),
        yara_hits=unavailable_yara_scan_result("test_disabled", status="disabled"),
        prev_stage="unknown",
        curr_stage="binary",
        suspicious=False,
        global_raw_info=None,
        raw_info_available=False,
        started_file=0.0,
        slow_file_warn_sec=0.0,
        active_timeout_budget=_Budget(),
        cache_sha256="",
        compiled_rules=None,
        analyze_file_full_observe_only=analyze,
        scan_session_snapshot="session",
        artifact_read_snapshot="artifact",
        routing_evidence_context=context,
        router_identity=identity,
    )

    assert completed_path == target
    assert observed["router_identity"] == identity
    assert observed["routing_evidence_context"] is context
    assert result[INMEMORY_ROUTE_IDENTITY_FIELD] == identity
    assert result[INMEMORY_ROUTE_IDENTITY_FIELD] == identity


def test_parent_publication_consumes_worker_route_identity_without_exposing_it(tmp_path: Path) -> None:
    target = tmp_path / "sample.imgblob"
    target.write_bytes(b"data")
    identity = _router_identity()
    captured: dict[str, object] = {}

    def attacher(record: dict[str, object], path: object, **kwargs: object) -> dict[str, object]:
        captured["path"] = path
        captured.update(kwargs)
        return dict(record)

    result = {
        "file": str(target),
        "path": str(target),
        "tags": ["filetype_binary"],
        "class": "benign_clean",
        "classification": "benign_clean",
        INMEMORY_ROUTE_IDENTITY_FIELD: identity,
    }
    published = attach_inmemory_result_evidence(
        result=result,
        record={"started_at": 1.0, "last_heartbeat": 1.0, "last_progress_time": 1.0},
        path=target,
        worker_pid=123,
        container_root=tmp_path,
        evidence_context=RoutingEvidenceContext.build(tmp_path),
        routing_evidence_attacher=attacher,
        wall_time=lambda: 2.0,
    )

    assert captured["router_identity"] == identity
    assert INMEMORY_ROUTE_IDENTITY_FIELD not in published


def test_serial_scheduler_never_uses_prior_file_stage_as_current_file_evidence() -> None:
    stages: list[str] = []

    def worker(path: str, previous_stage: str, _strict: bool) -> tuple[str, dict[str, object]]:
        stages.append(previous_stage)
        return path, {
            "effective_stage": "script" if path.endswith(".py") else "binary",
            "tags": ["script" if path.endswith(".py") else "binary"],
        }

    result = run_scheduler_serial_mode(
        SchedulerSerialModeRequest(
            files=("first.py", "second.bin"),
            total_files=2,
            started_at=0.0,
            progress_every=1,
            throttle_sec=0.0,
        ),
        SchedulerSerialModeDependencies(
            worker=worker,
            prepare_result=lambda _path, record: record,
            write_derived_cache=lambda _result: False,
            write_partial=lambda _force: None,
            bulk_scan_maintenance=lambda _count: None,
            log_bulk_progress=lambda *_args, **_kwargs: None,
            sleep=lambda _seconds: None,
        ),
    )

    assert tuple(result.results) == ("first.py", "second.bin")
    assert stages == ["unknown", "unknown"]


def test_worker_route_identity_transport_is_plain_recursive_pickle_payload() -> None:
    outcome = RouteScanOutcome(
        tags=("filetype_binary",),
        suspicious=False,
        identity={
            "magic_type": "pe_mz",
            "static_program_analysis": {
                "parser_status": "not_applicable",
                "limitations": ("bounded",),
            },
            "scanner_execution_plan": {
                "decisions": ({"scanner_id": "binary_static", "plan_status": "selected"},),
            },
        },
    )
    record: dict[str, object] = {"file": "sample.bin", "tags": []}
    attach_inmemory_route_identity(record, outcome.identity)

    transported = pickle.loads(pickle.dumps(record))
    identity = consume_inmemory_route_identity(transported)

    assert type(identity) is dict
    assert type(identity["static_program_analysis"]) is dict
    assert type(identity["scanner_execution_plan"]) is dict
    decisions = identity["scanner_execution_plan"]["decisions"]
    assert type(decisions) is tuple
    assert type(decisions[0]) is dict
    assert identity["magic_type"] == "pe_mz"


def test_worker_route_identity_transport_keeps_unavailable_identity_explicit() -> None:
    record: dict[str, object] = {"file": "sample.bin", "tags": []}
    assert attach_inmemory_route_identity(record, "not-a-mapping") is record
    assert INMEMORY_ROUTE_IDENTITY_FIELD not in record
