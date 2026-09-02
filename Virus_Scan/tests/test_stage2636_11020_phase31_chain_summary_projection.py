from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from Virus_Scan.contracts.chain_evidence import ChainEvent, ChainEvidence
from Virus_Scan.contracts.detection_observation import ObservationSourceLocation
from Virus_Scan.detection.chains.execution.matching import evaluate_chain_rule
from Virus_Scan.detection.registries.chain_registry import (
    CHAIN_REGISTRY_DIGEST,
    CHAIN_REGISTRY_VERSION,
    CHAIN_RULE_INDEX,
)
from Virus_Scan.publication.chain_summary import build_chain_findings_summary
from Virus_Scan.publication.json_finalization.success_fields import compact_success_analysis_fields
from Virus_Scan.publication.report_set import (
    build_scan_publication_snapshot,
    publish_scan_report_set,
    verify_report_manifest,
)
from Virus_Scan.runtime.resource_paths import build_scan_log_output_plan
from Virus_Scan.virustotal.contracts import VirusTotalReportingResult


def _chain_evidence() -> ChainEvidence:
    rule = CHAIN_RULE_INDEX["anchor:api_process_injection"]
    events = tuple(
        ChainEvent(
            evidence_id=f"ev_{index}",
            root_evidence_id=f"obs_phase31_root_{index}",
            term=term,
            source="tag_evidence",
            ordinal=index,
            observation_id=f"obs_phase31_event_{index}",
            correlation_group="injection",
            modality="static_control_flow",
            platform="windows",
            target_identity="target:process",
            process_identity="process:actor",
            artifact_identity="sha256:" + "a" * 64,
            source_location=ObservationSourceLocation(
                location_type="static_operation",
                locator="sample.exe",
                event_id=f"op_{index}",
            ),
            timing_provenance="static_control_flow",
            integrity_status="verified",
            directness="direct",
        )
        for index, term in enumerate(("writeprocessmemory", "createremotethread"))
    )
    decision = evaluate_chain_rule(rule, events)
    assert decision is not None
    assert decision.status == "confirmed"
    return ChainEvidence(
        registry_version=CHAIN_REGISTRY_VERSION,
        registry_digest=CHAIN_REGISTRY_DIGEST,
        decisions=(decision,),
    )


def _snapshot(tmp_path: Path, local_results: dict[str, object]):
    plan = build_scan_log_output_plan(
        scan_id="scan-00000000000000000031-aaaaaaaaaaaaaaaaaaaa",
        root=tmp_path / "Scan Logs",
    )
    staging = Path(plan.staging_path)
    staging.mkdir(parents=True)
    (staging / "scan_results.json").write_text(
        json.dumps(local_results, sort_keys=True),
        encoding="utf-8",
    )
    (staging / "scanlog").write_text("[SCAN] complete\n", encoding="utf-8")
    vt = VirusTotalReportingResult(
        status="unconfigured",
        config_digest="b" * 64,
        config_path=(tmp_path / "VirusTotal/virustotal_config.toml").as_posix(),
        api_key_environment_variable="VIRUSTOTAL_API_KEY",
    )
    return plan, build_scan_publication_snapshot(
        output_plan=plan,
        local_results=local_results,
        ledger_summary={"record_count": len(local_results), "ledger_digest": "c" * 64},
        virustotal_result=vt,
        persistence_status={"ok": True},
        max_score=0.0,
        elapsed_sec=1.0,
        scan_had_error=False,
        session_generation_id="d" * 64,
    )


def test_phase31_projection_preserves_exact_final_chain_decision_semantics() -> None:
    evidence = _chain_evidence()
    source_decision = evidence.decisions[0]
    source_rule = source_decision.rule
    summary = build_chain_findings_summary(
        scan_id="scan-31",
        snapshot_semantic_digest="8" * 64,
        local_results={"sample.exe": {"sha256": "a" * 64, "canonical_chain_evidence": evidence.to_record()}},
    )

    assert summary.counts_record()["decision_count"] == 1
    row = summary.finding_rows[0]
    assert row.content_sha256 == "a" * 64
    assert row.chain_id == source_decision.candidate.chain_id
    assert row.chain_name == source_decision.candidate.chain_id
    assert row.chain_name_source == "canonical_chain_id"
    assert row.rule_version == source_rule.version
    assert row.family == source_rule.family
    assert row.decision_status == source_decision.status
    assert row.match_mode == source_rule.match_mode
    assert row.order_provenance == source_decision.candidate.order_class == "static_control_flow"
    assert row.required_steps == tuple(step.alternatives for step in source_rule.steps if not step.optional)
    assert row.optional_steps == tuple(step.alternatives for step in source_rule.steps if step.optional)
    assert row.optional_evidence == source_rule.optional_evidence
    assert row.forbidden_evidence == source_rule.forbidden_evidence
    assert row.matched_step_indexes == (0, 1)
    assert row.missing_step_indexes == source_decision.candidate.missing_step_indexes
    assert row.unmet_requirements == source_decision.candidate.unmet_requirements
    assert row.root_evidence_ids == tuple(sorted(source_decision.candidate.distinct_root_ids))
    assert row.matched_evidence_ids == ("ev_0", "ev_1")
    assert row.operation_ids == ("op_0", "op_1")
    assert row.target_identities == ("target:process",)
    assert row.process_identities == ("process:actor",)
    assert row.same_target_required is source_rule.same_target
    assert row.same_process_required is source_rule.same_process
    assert row.same_artifact_required is source_rule.same_artifact
    assert row.same_resource_required is False
    assert row.resource_requirement_state == "represented_by_target_identity"
    assert row.same_flow_required is False
    assert row.flow_requirement_state == "not_declared_by_current_chain_rule_contract"
    assert row.required_fields == source_rule.required_fields
    assert row.required_platforms == source_rule.required_platforms
    assert row.required_modalities == source_rule.required_modalities
    assert row.confidence == source_decision.candidate.confidence
    assert row.support == source_decision.candidate.support
    assert row.scoreable is source_decision.scoreable
    assert row.score_points == source_decision.score_points
    assert row.operational_severity == source_decision.operational_severity
    assert row.anchor_floor == source_decision.anchor_floor
    assert row.report_time_reevaluated is False
    assert row.evidence_authority == "canonical_chain_decision_projection"


def test_phase31_compact_finalization_promotes_exact_chain_evidence_once() -> None:
    record = _chain_evidence().to_record()
    fields = compact_success_analysis_fields(
        {"chains": ["anchor:api_process_injection"], "canonical_chain_evidence": record},
        {"explanation": {"other": "kept"}, "reasons": []},
    )
    assert fields["canonical_chain_evidence"] == record
    assert fields["explanation"]["other"] == "kept"
    assert "canonical_chain_evidence" not in fields["explanation"]


def test_phase31_duplicate_path_aliases_do_not_duplicate_chain_decision() -> None:
    record = {"sha256": "a" * 64, "canonical_chain_evidence": _chain_evidence().to_record()}
    summary = build_chain_findings_summary(
        scan_id="scan-31",
        snapshot_semantic_digest="8" * 64,
        local_results={"first.exe": record, "alias.exe": record},
    )
    assert summary.source_record_count == 2
    assert summary.evidence_record_count == 2
    assert summary.duplicate_alias_count == 1
    assert len(summary.source_rows) == 1
    assert len(summary.finding_rows) == 1
    assert summary.source_rows[0].record_keys == ("alias.exe", "first.exe")
    assert summary.finding_rows[0].record_keys == ("alias.exe", "first.exe")


def test_phase31_conflicting_decisions_for_same_physical_roots_fail_closed() -> None:
    first = _chain_evidence().to_record()
    second = copy.deepcopy(first)
    second_decision = second["decisions"][0]
    second_decision["status"] = "candidate"
    second["confirmed_count"] = 0
    second["candidate_count"] = 1
    with pytest.raises(RuntimeError, match="chain_summary_physical_decision_conflict"):
        build_chain_findings_summary(
            scan_id="scan-31",
            snapshot_semantic_digest="8" * 64,
            local_results={
                "first.exe": {"sha256": "a" * 64, "canonical_chain_evidence": first},
                "conflict.exe": {"sha256": "a" * 64, "canonical_chain_evidence": second},
            },
        )


def test_phase31_identical_local_root_ids_on_distinct_artifacts_are_not_conflicts() -> None:
    first = _chain_evidence().to_record()
    second = copy.deepcopy(first)
    second_decision = second["decisions"][0]
    second_decision["status"] = "candidate"
    second["confirmed_count"] = 0
    second["candidate_count"] = 1

    summary = build_chain_findings_summary(
        scan_id="scan-31",
        snapshot_semantic_digest="8" * 64,
        local_results={
            "first.exe": {"sha256": "a" * 64, "canonical_chain_evidence": first},
            "second.exe": {"sha256": "b" * 64, "canonical_chain_evidence": second},
        },
    )

    assert summary.duplicate_alias_count == 0
    assert len(summary.source_rows) == 2
    assert len(summary.finding_rows) == 2
    assert {row.content_sha256 for row in summary.finding_rows} == {"a" * 64, "b" * 64}


def test_phase31_parent_transaction_publishes_and_manifests_all_chain_formats(tmp_path: Path) -> None:
    evidence = _chain_evidence()
    local_results = {
        "sample.exe": {
            "classification": "benign_clean",
            "score": 0.0,
            "sha256": "a" * 64,
            "canonical_chain_evidence": evidence.to_record(),
        }
    }
    plan, snapshot = _snapshot(tmp_path, local_results)
    publication = publish_scan_report_set(snapshot)

    run = Path(plan.run_path)
    for name in ("chain_findings_summary.json", "chain_findings_summary.md", "chain_findings_summary.csv"):
        assert (run / name).is_file()
    summary_record = json.loads((run / "chain_findings_summary.json").read_text(encoding="utf-8"))
    manifest = verify_report_manifest(run)
    latest = json.loads(Path(plan.latest_path).read_text(encoding="utf-8"))
    assert manifest.chain_summary_semantic_digest == summary_record["summary_semantic_digest"]
    assert manifest.chain_decision_count == 1
    assert manifest.chain_evidence_record_count == 1
    assert manifest.chain_unique_evidence_count == 1
    assert manifest.chain_duplicate_alias_count == 0
    assert latest["chain_summary_semantic_digest"] == manifest.chain_summary_semantic_digest
    assert latest["chain_decision_count"] == 1
    assert publication.chain_summary_semantic_digest == manifest.chain_summary_semantic_digest
    assert publication.chain_decision_count == 1


def test_phase31_chain_summary_tamper_is_rejected(tmp_path: Path) -> None:
    plan, snapshot = _snapshot(
        tmp_path,
        {"sample.exe": {"sha256": "a" * 64, "canonical_chain_evidence": _chain_evidence().to_record()}},
    )
    publish_scan_report_set(snapshot)
    summary_path = Path(plan.run_path) / "chain_findings_summary.json"
    record = json.loads(summary_path.read_text(encoding="utf-8"))
    record["counts"]["decision_count"] = 99
    summary_path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    with pytest.raises(RuntimeError, match="report_manifest_file_mismatch"):
        verify_report_manifest(plan.run_path)


def test_phase31_invalid_present_chain_evidence_blocks_activation(tmp_path: Path) -> None:
    plan, snapshot = _snapshot(
        tmp_path,
        {"sample.exe": {"sha256": "a" * 64, "canonical_chain_evidence": {"schema_version": "invalid"}}},
    )
    with pytest.raises(RuntimeError, match="chain_summary_source_schema_invalid"):
        publish_scan_report_set(snapshot)
    assert Path(plan.staging_path).is_dir()
    assert not Path(plan.run_path).exists()
    assert not Path(plan.latest_path).exists()


def test_phase31_projector_has_no_registry_evaluator_or_filesystem_writer_owner() -> None:
    source = Path("Virus_Scan/publication/chain_summary.py").read_text(encoding="utf-8")
    assert "Virus_Scan.detection.registries" not in source
    assert "evaluate_chain" not in source
    assert "scan_file" not in source
    assert "ThreadPoolExecutor" not in source
    assert "ProcessPoolExecutor" not in source
    assert ".write_text(" not in source
    assert ".write_bytes(" not in source
