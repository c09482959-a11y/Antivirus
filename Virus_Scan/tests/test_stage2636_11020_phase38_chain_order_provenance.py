"""Phase 38 ordered-Chain provenance-domain acceptance gates."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.contracts.chain_evidence import CHAIN_EVIDENCE_GENERATION_SCHEMA_VERSION
from Virus_Scan.detection.api.runner import analyze_file_full_observe_only
from Virus_Scan.detection.chains.execution.anchors import (
    evaluate_chain_evidence,
    evaluate_chain_evidence_generation,
)
from Virus_Scan.detection.chains.execution.compiled_registry import (
    COMPILED_CHAIN_REGISTRY_VERSION,
)
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.scanners.static_program_analysis.python_frontend import analyze_python_renpy_snapshot
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture


_INJECTION_CHAIN = "static.artifact.virtualallocex_writeprocessmemory_createremotethread"
_INJECTION_SOURCE = (
    "import ctypes\n"
    "kernel32 = ctypes.windll.kernel32\n"
    "process = kernel32.OpenProcess(0x1F0FFF, False, 1234)\n"
    "remote = kernel32.VirtualAllocEx(process, None, 4096, 0x3000, 0x40)\n"
    "kernel32.WriteProcessMemory(process, remote, b'abc', 3, None)\n"
    "kernel32.CreateRemoteThread(process, None, 0, remote, None, 0, None)\n"
)


def _route(tmp_path: Path):
    target = tmp_path / "injection.py"
    target.write_text(_INJECTION_SOURCE, encoding="utf-8")
    session = scan_session_snapshot_fixture()
    outcome = scan_file_by_type(
        str(target),
        scan_session_snapshot=session,
        artifact_read_snapshot=build_artifact_read_snapshot(target),
    )
    return target, session, outcome


def _decision(evidence, chain_id: str):
    return next(
        item for item in evidence.decisions
        if item.to_record()["chain_id"] == chain_id
    )


def test_phase38_full_analysis_preserves_validated_static_order_when_runtime_order_exists(
    tmp_path: Path,
) -> None:
    target, session, outcome = _route(tmp_path)
    static_analysis = analyze_python_renpy_snapshot(build_artifact_read_snapshot(target)).analysis
    tags_only_chain = _decision(
        evaluate_chain_evidence(tags=outcome.tag_evidence), _INJECTION_CHAIN,
    ).to_record()
    assert tags_only_chain["status"] == "candidate"
    assert any("operation_unavailable" in item for item in tags_only_chain["unmet_requirements"])
    route_chain = _decision(
        evaluate_chain_evidence(
            tags=outcome.tag_evidence,
            static_program_analyses=(static_analysis,),
        ),
        _INJECTION_CHAIN,
    ).to_record()
    assert route_chain["status"] == "confirmed"
    assert route_chain["order_class"] == "static_control_flow"

    result = analyze_file_full_observe_only(
        str(target),
        tags=outcome.tag_evidence,
        yara_hits=(),
        curr_stage="py",
        strings_blob=_INJECTION_SOURCE,
        strings_already_enriched=False,
        scan_session_snapshot=session,
        artifact_read_snapshot=build_artifact_read_snapshot(target),
        static_program_analyses=outcome.static_program_analyses,
        router_identity=outcome.identity,
    )
    assert result["behavior_timeline"]
    assert result["ordered_events"]
    final_chain = next(
        item for item in result["canonical_chain_evidence"]["decisions"]
        if item["chain_id"] == _INJECTION_CHAIN
    )
    # Phase 11 carries the exact router-produced StaticProgramAnalysis into
    # full-analysis Chain evaluation.  Confirmation is therefore rooted in the
    # same static operations/flow, without rerunning the frontend or laundering
    # projected tags into causality authority.
    assert final_chain["status"] == "confirmed"
    assert final_chain["order_class"] == "static_control_flow"
    assert final_chain["unmet_requirements"] == []
    assert final_chain["scoreable"] is False
    assert final_chain["score_points"] == 0.0
    events = tuple(step["event"] for step in final_chain["matched_steps"])
    assert tuple(event["ordinal"] for event in events) == (1, 2, 3)
    assert all(event["timing_provenance"] == "static_control_flow" for event in events)
    assert all(event["modality"] == "static_control_flow" for event in events)
    assert all(event["platform"] == "windows" for event in events)


def test_phase38_static_only_rule_reuse_is_independent_of_monotonic_runtime_extension(
    tmp_path: Path,
) -> None:
    target, _session, outcome = _route(tmp_path)
    static_analysis = analyze_python_renpy_snapshot(build_artifact_read_snapshot(target)).analysis
    first = evaluate_chain_evidence_generation(
        tags=outcome.tag_evidence,
        ordered_events=({"event": "network_download", "timestamp": 1.0},),
        rule_ids=(_INJECTION_CHAIN,),
        static_program_analyses=(static_analysis,),
    )
    first_record = first.to_record()
    assert first_record["schema_version"] == "stage2636_11020_chain_evidence_generation_v4"
    assert "ordered_event_digest" not in first_record
    assert first.runtime_ordered_event_digest != first.static_ordered_event_digest
    assert _decision(first.evidence, _INJECTION_CHAIN).status == "confirmed"

    extended = evaluate_chain_evidence_generation(
        tags=outcome.tag_evidence,
        ordered_events=(
            {"event": "network_download", "timestamp": 1.0},
            {"event": "process_exec", "timestamp": 2.0},
        ),
        rule_ids=(_INJECTION_CHAIN,),
        static_program_analyses=(static_analysis,),
        previous_generation=first,
    )
    assert extended.full_recompute_reason == ""
    assert extended.evaluated_rule_ids == ()
    assert extended.reused_rule_ids == (_INJECTION_CHAIN,)
    assert extended.runtime_ordered_event_digest != first.runtime_ordered_event_digest
    assert extended.static_ordered_event_digest == first.static_ordered_event_digest
    assert extended.outcomes[0].input_digest == first.outcomes[0].input_digest
    assert _decision(extended.evidence, _INJECTION_CHAIN).status == "confirmed"


def test_phase38_order_provenance_contract_versions_invalidate_prior_compiled_identity() -> None:
    assert CHAIN_EVIDENCE_GENERATION_SCHEMA_VERSION == (
        "stage2636_11020_chain_evidence_generation_v4"
    )
    assert COMPILED_CHAIN_REGISTRY_VERSION == "stage2636_11020_compiled_chain_registry_v4"
