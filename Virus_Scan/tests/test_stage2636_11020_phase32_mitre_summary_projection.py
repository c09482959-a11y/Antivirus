from __future__ import annotations

from Virus_Scan.tests.support.attack_mapping_contract_fixtures import attack_mapping_evidence_fixture

import copy
import json
from pathlib import Path

import pytest

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.attack.mapping.mapper import map_attack_evidence
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICY_BY_ID
from Virus_Scan.detection.api.attack_mapping_contracts import ATTACK_MAPPING_SCHEMA_VERSION
from Virus_Scan.detection.attack.versioning import (
    ATTACK_EVALUATION_PROVENANCE,
    ATTACK_MAPPING_POLICY_VERSION,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.publication.mitre_summary import build_mitre_findings_summary
from Virus_Scan.publication.report_set import (
    build_scan_publication_snapshot,
    publish_scan_report_set,
    verify_report_manifest,
)
from Virus_Scan.runtime.resource_paths import build_scan_log_output_plan
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import (
    attack_chain_contract_fixture,
    attack_contract_repository,
    attack_explainability_context_fixture,
)
from Virus_Scan.virustotal.contracts import VirusTotalReportingResult


def _ready_sources() -> tuple[dict[str, object], dict[str, object], object]:
    repository = attack_contract_repository()
    policy = ATTACK_TECHNIQUE_POLICY_BY_ID["T1055"]
    chain_evidence = attack_chain_contract_fixture(
        policy,
        "phase32",
        status="confirmed",
        root_count=3,
    )
    artifact_evidence = attack_mapping_evidence_fixture(TagEvidence(), chain_evidence)
    mapping = map_attack_evidence(repository, artifact_evidence)
    _candidate_context, _plan, explainability = attack_explainability_context_fixture(
        artifact_evidence, mapping, reason="phase32_summary_projection",
    )
    decision = next(item for item in mapping.decisions if item.technique_id == "T1055")
    assert decision.status == "candidate"
    assert decision.claim_scopes == ("artifact_implementation",)
    assert decision.execution_observed is False

    evidence = mapping.to_record()
    evidence["confirmed"] = ()
    evidence["candidate"] = (decision.to_record(),)
    evidence["rejected"] = ()
    evidence["unavailable"] = ()
    evidence["mapping_scope"] = "official_attack_techniques"
    evidence["technique_ids_claimed"] = False
    evidence["repository_status"] = {
        "available": True,
        "repository_digest": repository.digest,
        "dataset_version": repository.version.dataset_version,
    }
    evidence["verified_yara_observation_count"] = 0
    evidence["yara_alignment_count"] = 0

    chain_record = copy.deepcopy(chain_evidence.to_record())
    for index, step in enumerate(chain_record["decisions"][0]["matched_steps"]):
        step["event"]["source_location"]["location_type"] = "static_operation"
        step["event"]["source_location"]["event_id"] = f"static-op-{index}"

    local_record = {
        "sha256": "a" * 64,
        "classification": "benign_clean",
        "score": 0.0,
        "model_evidence": {"mitre_evidence": evidence},
        "canonical_chain_evidence": chain_record,
        "attack_explainability": explainability.to_record(),
    }
    return local_record, evidence, decision


def _unavailable_record(reason: str = "mitre_repository_unavailable") -> dict[str, object]:
    evidence = {
        "schema_version": ATTACK_MAPPING_SCHEMA_VERSION,
        "repository_digest": "",
        "dataset_version": "",
        "ready": False,
        "probability": 0.0,
        "probability_unavailable_reason": "",
        "unavailable_reason": reason,
        "policy_version": ATTACK_MAPPING_POLICY_VERSION,
        "evaluation_provenance": ATTACK_EVALUATION_PROVENANCE,
        "confirmed": (),
        "candidate": (),
        "rejected": (),
        "unavailable": (),
        "mapping_scope": "official_attack_techniques",
        "technique_ids_claimed": False,
        "repository_status": {"available": False, "unavailable_reason": reason},
        "verified_yara_observation_count": 0,
        "yara_alignment_count": 0,
    }
    return {
        "sha256": "a" * 64,
        "classification": "benign_clean",
        "score": 0.0,
        "model_evidence": {"mitre_evidence": evidence},
    }


def _snapshot(tmp_path: Path, local_results: dict[str, object]):
    plan = build_scan_log_output_plan(
        scan_id="scan-00000000000000000032-aaaaaaaaaaaaaaaaaaaa",
        root=tmp_path / "Scan Logs",
    )
    staging = Path(plan.staging_path)
    staging.mkdir(parents=True)
    (staging / "scan_results.json").write_text(
        json.dumps(local_results, sort_keys=True), encoding="utf-8"
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


def test_phase32_projection_preserves_exact_candidate_static_semantics() -> None:
    record, _evidence, decision = _ready_sources()
    summary = build_mitre_findings_summary(
        scan_id="scan-32",
        snapshot_semantic_digest="8" * 64,
        local_results={"sample.exe": record},
    )

    counts = summary.counts_record()
    assert counts["decision_count"] == 1
    assert counts["confirmed_count"] == 0
    assert counts["candidate_count"] == 1
    assert counts["rejected_count"] == 0
    row = summary.finding_rows[0]
    assert row.content_sha256 == "a" * 64
    assert row.technique_id == "T1055"
    assert row.technique_name == "Process Injection"
    assert row.tactic_ids == ("TA0005",)
    assert row.tactic_names == ("Defense Evasion",)
    assert row.decision_status == "candidate"
    assert row.claim_scopes == ("artifact_implementation",)
    assert row.execution_observed is False
    assert row.policy_implementation_ids == decision.policy_implementation_ids
    assert row.implementation_ids == decision.implementation_ids
    assert row.required_chain_ids == decision.required_chain_ids
    assert row.required_chain_states == (
        "static.artifact.virtualallocex_writeprocessmemory_createremotethread=confirmed",
    )
    assert row.operation_ids == ("static-op-0", "static-op-1", "static-op-2")
    assert row.required_platforms == ("windows",)
    assert row.required_modalities == (
        "dynamic_runtime",
        "host_telemetry",
        "static_control_flow",
    )
    assert row.root_evidence_ids == decision.root_evidence_ids
    assert row.probability == 0.0
    assert row.probability_unavailable_reason == "candidate_not_scoreable"
    assert row.policy_admission_state == "candidate_only"
    assert row.calibration_artifact_id == ""
    assert row.authority_requirement_root_bindings
    assert any("static.artifact.virtualallocex_writeprocessmemory_createremotethread" in item for item in row.authority_requirement_root_bindings)
    assert row.authority_relation_requirements
    assert all('"same_resource":true' in item for item in row.authority_relation_requirements)
    assert row.physical_root_provenance
    assert row.deterministic_derivations == (
        "static.artifact.virtualallocex_writeprocessmemory_createremotethread|confirmed",
    )
    assert row.yara_role == "absent"
    assert row.yara_used_root_evidence_ids == ()
    assert row.model_assistance_evidence_authority == "context_only"
    assert row.model_assistance_official_decision_effect == "none"
    assert len(row.attack_explainability_semantic_digest) == 64
    assert len(row.authority_chain_semantic_digest) == 64


def test_phase32_required_chain_absent_from_final_chain_evidence_is_explicit_not_recomputed() -> None:
    repository = attack_contract_repository()
    policy = ATTACK_TECHNIQUE_POLICY_BY_ID["T1055"]
    chain_evidence = attack_chain_contract_fixture(
        policy,
        "phase32-missing-chain",
        status="confirmed",
        root_count=3,
    )
    artifact_evidence = attack_mapping_evidence_fixture(TagEvidence(), chain_evidence)
    mapping = map_attack_evidence(repository, artifact_evidence)
    _candidate_context, _plan, explainability = attack_explainability_context_fixture(
        artifact_evidence, mapping, reason="phase32_missing_chain_projection",
    )
    t1003 = next(item for item in mapping.decisions if item.technique_id == "T1003")
    assert t1003.status == "rejected"
    assert t1003.required_chain_ids == (
        "anchor:api_lsass_minidump",
        "execution.lsass_process_access_to_dump",
    )

    evidence = mapping.to_record()
    evidence["confirmed"] = ()
    evidence["candidate"] = ()
    evidence["rejected"] = (t1003.to_record(),)
    evidence["mapping_scope"] = "official_attack_techniques"
    evidence["technique_ids_claimed"] = False
    evidence["repository_status"] = {
        "available": True,
        "repository_digest": repository.digest,
        "dataset_version": repository.version.dataset_version,
    }
    evidence["verified_yara_observation_count"] = 0
    evidence["yara_alignment_count"] = 0
    record = {
        "sha256": "a" * 64,
        "classification": "benign_clean",
        "score": 0.0,
        "model_evidence": {"mitre_evidence": evidence},
        "canonical_chain_evidence": chain_evidence.to_record(),
        "attack_explainability": explainability.to_record(),
    }

    summary = build_mitre_findings_summary(
        scan_id="scan-32",
        snapshot_semantic_digest="8" * 64,
        local_results={"sample.exe": record},
    )
    row = summary.finding_rows[0]
    assert row.technique_id == "T1003"
    assert row.decision_status == "rejected"
    assert row.required_chain_states == (
        "anchor:api_lsass_minidump=not_present_in_final_chain_evidence",
        "execution.lsass_process_access_to_dump=not_present_in_final_chain_evidence",
    )
    assert row.required_evidence_terms == ()
    assert row.optional_evidence_terms == ()
    assert row.forbidden_evidence_terms == ()
    assert row.operation_ids == ()


def test_phase32_unavailable_is_explicit_and_never_negative() -> None:
    summary = build_mitre_findings_summary(
        scan_id="scan-32",
        snapshot_semantic_digest="8" * 64,
        local_results={"sample.exe": _unavailable_record()},
    )
    counts = summary.counts_record()
    assert counts["unavailable_evidence_count"] == 1
    assert counts["decision_count"] == 0
    assert summary.source_rows[0].ready is False
    assert summary.source_rows[0].unavailable_reason == "mitre_repository_unavailable"
    assert summary.source_rows[0].probability == 0.0


def test_phase32_duplicate_path_aliases_do_not_duplicate_mitre_decision() -> None:
    record, _evidence, _decision = _ready_sources()
    summary = build_mitre_findings_summary(
        scan_id="scan-32",
        snapshot_semantic_digest="8" * 64,
        local_results={"first.exe": record, "alias.exe": record},
    )
    assert summary.source_record_count == 2
    assert summary.evidence_record_count == 2
    assert summary.duplicate_alias_count == 1
    assert len(summary.source_rows) == 1
    assert len(summary.finding_rows) == 1
    assert summary.finding_rows[0].record_keys == ("alias.exe", "first.exe")


def test_phase32_identical_local_chain_projection_on_distinct_content_is_not_an_alias_or_conflict() -> None:
    first, _evidence, _decision = _ready_sources()
    second = copy.deepcopy(first)
    second["sha256"] = "b" * 64
    second["canonical_chain_evidence"]["decisions"][0]["matched_steps"][0]["event"]["source_location"]["event_id"] = "different-op"
    summary = build_mitre_findings_summary(
        scan_id="scan-32",
        snapshot_semantic_digest="8" * 64,
        local_results={"first.exe": first, "second.exe": second},
    )
    assert summary.duplicate_alias_count == 0
    assert len(summary.source_rows) == 2
    assert len(summary.finding_rows) == 2
    assert {row.content_sha256 for row in summary.finding_rows} == {"a" * 64, "b" * 64}


def test_phase32_present_mitre_evidence_requires_canonical_content_sha256() -> None:
    record, _evidence, _decision = _ready_sources()
    del record["sha256"]
    with pytest.raises(ValueError, match="mitre_summary_content_sha256_invalid:sample.exe"):
        build_mitre_findings_summary(
            scan_id="scan-32",
            snapshot_semantic_digest="8" * 64,
            local_results={"sample.exe": record},
        )


def test_phase32_conflicting_mitre_decisions_for_same_physical_roots_fail_closed() -> None:
    first, _evidence, _decision = _ready_sources()
    second = copy.deepcopy(first)
    second["model_evidence"]["mitre_evidence"]["candidate"][0]["technique_name"] = "Conflicting Name"
    with pytest.raises(RuntimeError, match="mitre_summary_physical_decision_conflict:T1055"):
        build_mitre_findings_summary(
            scan_id="scan-32",
            snapshot_semantic_digest="8" * 64,
            local_results={"first.exe": first, "conflict.exe": second},
        )


def test_phase32_alias_chain_projection_conflict_fails_closed() -> None:
    first, _evidence, _decision = _ready_sources()
    second = copy.deepcopy(first)
    second["canonical_chain_evidence"]["decisions"][0]["matched_steps"][0]["event"]["source_location"]["event_id"] = "different-op"
    with pytest.raises(RuntimeError, match="mitre_summary_chain_projection_conflict:T1055"):
        build_mitre_findings_summary(
            scan_id="scan-32",
            snapshot_semantic_digest="8" * 64,
            local_results={"first.exe": first, "conflict.exe": second},
        )


def test_phase32_parent_transaction_publishes_and_manifests_all_mitre_formats(tmp_path: Path) -> None:
    record, _evidence, _decision = _ready_sources()
    plan, snapshot = _snapshot(tmp_path, {"sample.exe": record})
    publication = publish_scan_report_set(snapshot)

    run = Path(plan.run_path)
    for name in (
        "mitre_findings_summary.json",
        "mitre_findings_summary.md",
        "mitre_findings_summary.csv",
    ):
        assert (run / name).is_file()
    summary_record = json.loads((run / "mitre_findings_summary.json").read_text(encoding="utf-8"))
    manifest = verify_report_manifest(run)
    latest = json.loads(Path(plan.latest_path).read_text(encoding="utf-8"))
    assert manifest.mitre_summary_semantic_digest == summary_record["summary_semantic_digest"]
    assert manifest.mitre_decision_count == 1
    assert manifest.mitre_confirmed_count == 0
    assert manifest.mitre_candidate_count == 1
    assert manifest.mitre_rejected_count == 0
    assert latest["mitre_summary_semantic_digest"] == manifest.mitre_summary_semantic_digest
    assert latest["mitre_decision_count"] == 1
    assert publication.mitre_summary_semantic_digest == manifest.mitre_summary_semantic_digest
    assert publication.mitre_decision_count == 1


def test_phase32_parent_transaction_counts_and_explains_unavailable_decision(tmp_path: Path) -> None:
    record, evidence, _candidate = _ready_sources()
    repository = attack_contract_repository()
    full_mapping = map_attack_evidence(
        repository,
        attack_mapping_evidence_fixture(
            TagEvidence(), ChainEvidence("phase32-unavailable-v1", "phase32-unavailable"),
        ),
    )
    unavailable = next(
        item for item in full_mapping.decisions if item.technique_id == "T1041"
    )
    assert unavailable.status == "unavailable"
    assert unavailable.unavailable_reason == "unsupported_by_sensors"
    evidence["unavailable"] = (unavailable.to_record(),)

    plan, snapshot = _snapshot(tmp_path, {"sample.exe": record})
    publish_scan_report_set(snapshot)
    run = Path(plan.run_path)
    manifest = verify_report_manifest(run)
    summary_record = json.loads(
        (run / "mitre_findings_summary.json").read_text(encoding="utf-8")
    )
    markdown = (run / "mitre_findings_summary.md").read_text(encoding="utf-8")
    csv_text = (run / "mitre_findings_summary.csv").read_text(encoding="utf-8")

    assert manifest.mitre_decision_count == 2
    assert manifest.mitre_candidate_count == 1
    assert manifest.mitre_rejected_count == 0
    assert manifest.mitre_unavailable_count == 1
    assert summary_record["counts"]["unavailable_decision_count"] == 1
    rows = {row["technique_id"]: row for row in summary_record["finding_rows"]}
    assert rows["T1041"]["decision_status"] == "unavailable"
    assert rows["T1041"]["unavailable_reason"] == "unsupported_by_sensors"
    assert rows["T1041"]["schema_version"] == "mitre_finding_summary_row_v4"
    assert "unsupported_by_sensors" in markdown
    assert "Model authority" in markdown
    assert "unavailable_reason" in csv_text.splitlines()[0]
    assert "authority_requirement_root_bindings" in csv_text.splitlines()[0]
    assert "yara_role" in csv_text.splitlines()[0]
    assert "unsupported_by_sensors" in csv_text


def test_phase32_mitre_summary_tamper_is_rejected(tmp_path: Path) -> None:
    record, _evidence, _decision = _ready_sources()
    plan, snapshot = _snapshot(tmp_path, {"sample.exe": record})
    publish_scan_report_set(snapshot)
    target = Path(plan.run_path) / "mitre_findings_summary.json"
    target.write_text("{}", encoding="utf-8")
    with pytest.raises(RuntimeError, match="report_manifest_file_mismatch"):
        verify_report_manifest(plan.run_path)


def test_phase32_projector_has_no_mapping_registry_chain_evaluator_or_writer_owner() -> None:
    source = (Path(__file__).resolve().parents[1] / "publication" / "mitre_summary.py").read_text(
        encoding="utf-8"
    )
    forbidden = (
        "detection.attack.mapping.mapper",
        "detection.attack.mapping.registry",
        "detection.attack.repository",
        "detection.attack.publication",
        "detection.registries.chain_registry",
        "detection.chains.execution",
        "evaluate_chain",
        "map_attack_evidence",
        "atomic_json_save",
        ".write_text(",
        ".write_bytes(",
    )
    for token in forbidden:
        assert token not in source
