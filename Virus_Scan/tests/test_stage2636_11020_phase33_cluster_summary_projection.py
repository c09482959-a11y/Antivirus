from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from Virus_Scan.detection.attack.candidate_retrieval import (
    AttackCandidateRank,
    AttackCandidateRetrievalResult,
    AttackClusterContext,
    unavailable_attack_candidate_retrieval,
)
from Virus_Scan.detection.api.attack_candidate_retrieval_contracts import (
    ATTACK_CANDIDATE_RETRIEVAL_SCHEMA_VERSION,
    ATTACK_CANDIDATE_RETRIEVAL_VERSION,
)
from Virus_Scan.publication.cluster_summary import build_cluster_findings_summary
from Virus_Scan.publication.report_set import (
    build_scan_publication_snapshot,
    publish_scan_report_set,
    verify_report_manifest,
)
from Virus_Scan.runtime.resource_paths import build_scan_log_output_plan
from Virus_Scan.virustotal.contracts import VirusTotalReportingResult


def _available_retrieval() -> AttackCandidateRetrievalResult:
    context = AttackClusterContext(
        cluster_id="cluster:phase33",
        cluster_model_version="cluster-model-v1",
        cluster_members=17,
        trusted_support=11,
        maturity=0.75,
        purity=0.90,
        drift=1.0,
        cluster_quality=0.80,
        tag_signature=("tag:a", "tag:b"),
        chain_signature=("chain:a",),
        behavior_signature=("behavior:a",),
        available=True,
        unavailable_reason="",
    )
    candidate = AttackCandidateRank(
        rank=1,
        technique_id="T1055",
        implementation_ids=("impl:t1055",),
        claim_scopes=("artifact_implementation",),
        admission_state="candidate_only",
        correlation_group="process_injection",
        score=0.875,
        matched_cluster_chain_ids=("chain:a",),
        matched_direct_chain_ids=("chain:direct",),
        shared_physical_root_ids=("root:a", "root:b"),
        missing_direct_requirements=("direct_static_operation",),
    )
    return AttackCandidateRetrievalResult(
        repository_digest="a" * 64,
        dataset_version="enterprise-attack-test",
        cluster_context=context,
        tag_signatures=("tag:direct",),
        chain_signatures=("chain:direct",),
        static_operation_signatures=("static-op:a",),
        markov_context_signal=0.25,
        temporal_context_signal=0.50,
        candidates=(candidate,),
        abstained=False,
        unavailable_reason="",
    )


def _record(
    retrieval: AttackCandidateRetrievalResult,
    *,
    sha256: str = "a" * 64,
) -> dict[str, object]:
    return {
        "sha256": sha256,
        "classification": "benign_clean",
        "score": 0.0,
        "model_evidence": {
            "attack_candidate_retrieval": retrieval.to_record(),
        },
        "tags": ("physical:unchanged",),
    }


def _snapshot(tmp_path: Path, local_results: dict[str, object]):
    plan = build_scan_log_output_plan(
        scan_id="scan-00000000000000000033-aaaaaaaaaaaaaaaaaaaa",
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


def test_phase33_projection_preserves_cluster_context_and_zero_authority() -> None:
    retrieval = _available_retrieval()
    summary = build_cluster_findings_summary(
        scan_id="scan-33",
        snapshot_semantic_digest="8" * 64,
        local_results={"sample.exe": _record(retrieval)},
    )
    counts = summary.counts_record()
    assert counts == {
        "source_record_count": 1,
        "evidence_record_count": 1,
        "unique_evidence_count": 1,
        "duplicate_alias_count": 0,
        "available_cluster_count": 1,
        "unavailable_cluster_count": 0,
        "candidate_count": 1,
    }
    row = summary.source_rows[0]
    assert row.content_sha256 == "a" * 64
    assert row.cluster_id == "cluster:phase33"
    assert row.cluster_model_version == "cluster-model-v1"
    assert row.cluster_members == 17
    assert row.trusted_support == 11
    assert row.maturity == 0.75
    assert row.purity == 0.90
    assert row.drift == 1.0
    assert row.drift_state == "drift_or_purity_alarm"
    assert row.cluster_quality == 0.80
    assert row.suspicious_member_count is None
    assert row.suspicious_member_count_unavailable_reason == "canonical_cluster_model_has_no_suspicious_label"
    assert row.evidence_authority == "context_only"
    assert row.eligible_for_confirmation is False
    assert row.eligible_for_probability is False
    assert row.official_decision_effect == "none"

    candidate = summary.candidate_rows[0]
    assert candidate.content_sha256 == "a" * 64
    assert candidate.technique_id == "T1055"
    assert candidate.rank == 1
    assert candidate.score == 0.875
    assert candidate.matched_cluster_chain_ids == ("chain:a",)
    assert candidate.matched_direct_chain_ids == ("chain:direct",)
    assert candidate.shared_physical_root_ids == ("root:a", "root:b")
    assert candidate.missing_direct_requirements == ("direct_static_operation",)
    assert candidate.evidence_authority == "context_only"
    assert candidate.eligible_for_confirmation is False
    assert candidate.eligible_for_probability is False
    assert candidate.official_decision_effect == "none"


def test_phase33_unavailable_cluster_is_explicit_unknown_not_zero_negative() -> None:
    retrieval = unavailable_attack_candidate_retrieval("mitre_repository_unavailable")
    summary = build_cluster_findings_summary(
        scan_id="scan-33",
        snapshot_semantic_digest="8" * 64,
        local_results={"sample.exe": _record(retrieval)},
    )
    row = summary.source_rows[0]
    assert row.available is False
    assert row.unavailable_reason == "mitre_repository_unavailable"
    assert row.cluster_members is None
    assert row.trusted_support is None
    assert row.maturity is None
    assert row.purity is None
    assert row.drift is None
    assert row.drift_state == "unavailable"
    assert row.cluster_quality is None
    assert summary.candidate_rows == ()


def test_phase33_duplicate_aliases_share_one_cluster_and_candidate_projection() -> None:
    record = _record(_available_retrieval())
    summary = build_cluster_findings_summary(
        scan_id="scan-33",
        snapshot_semantic_digest="8" * 64,
        local_results={"first.exe": record, "alias.exe": record},
    )
    assert summary.source_record_count == 2
    assert summary.evidence_record_count == 2
    assert summary.duplicate_alias_count == 1
    assert len(summary.source_rows) == 1
    assert len(summary.candidate_rows) == 1
    assert summary.source_rows[0].record_keys == ("alias.exe", "first.exe")
    assert summary.candidate_rows[0].record_keys == ("alias.exe", "first.exe")


def test_phase33_identical_cluster_evidence_on_distinct_content_is_not_an_alias() -> None:
    retrieval = _available_retrieval()
    first = _record(retrieval, sha256="a" * 64)
    second = _record(retrieval, sha256="b" * 64)
    summary = build_cluster_findings_summary(
        scan_id="scan-33",
        snapshot_semantic_digest="8" * 64,
        local_results={"first.exe": first, "second.exe": second},
    )
    assert summary.duplicate_alias_count == 0
    assert len(summary.source_rows) == 2
    assert len(summary.candidate_rows) == 2
    assert {row.content_sha256 for row in summary.source_rows} == {"a" * 64, "b" * 64}


def test_phase33_present_cluster_evidence_requires_canonical_content_sha256() -> None:
    record = _record(_available_retrieval())
    del record["sha256"]
    with pytest.raises(ValueError, match="cluster_summary_content_sha256_invalid:sample.exe"):
        build_cluster_findings_summary(
            scan_id="scan-33",
            snapshot_semantic_digest="8" * 64,
            local_results={"sample.exe": record},
        )


def test_phase33_tampered_candidate_retrieval_digest_fails_closed() -> None:
    record = _record(_available_retrieval())
    retrieval_record = record["model_evidence"]["attack_candidate_retrieval"]
    retrieval_record["ranked_candidates"][0]["score"] = 0.1
    with pytest.raises(RuntimeError, match="cluster_summary_source_digest_mismatch"):
        build_cluster_findings_summary(
            scan_id="scan-33",
            snapshot_semantic_digest="8" * 64,
            local_results={"sample.exe": record},
        )


def test_phase33_projection_is_read_only_for_local_and_mitre_state() -> None:
    record = _record(_available_retrieval())
    record["model_evidence"]["mitre_evidence"] = {"sentinel": "unchanged"}
    before = copy.deepcopy(record)
    summary = build_cluster_findings_summary(
        scan_id="scan-33",
        snapshot_semantic_digest="8" * 64,
        local_results={"sample.exe": record},
    )
    assert record == before
    assert record["model_evidence"]["mitre_evidence"] == {"sentinel": "unchanged"}
    assert record["tags"] == ("physical:unchanged",)
    policy = summary.to_record()["projection_policy"]
    assert policy["report_time_cluster_lookup"] is False
    assert policy["report_time_candidate_retrieval"] is False
    assert policy["report_time_attack_mapping"] is False
    assert policy["eligible_for_confirmation"] is False
    assert policy["eligible_for_probability"] is False
    assert policy["official_decision_effect"] == "none"


def test_phase33_parent_transaction_publishes_and_manifests_all_cluster_formats(tmp_path: Path) -> None:
    local_results = {"sample.exe": _record(_available_retrieval())}
    plan, snapshot = _snapshot(tmp_path, local_results)
    publication = publish_scan_report_set(snapshot)
    run = Path(plan.run_path)
    for name in ("cluster_findings_summary.json", "cluster_findings_summary.md", "cluster_findings_summary.csv"):
        assert (run / name).is_file()
    summary_record = json.loads((run / "cluster_findings_summary.json").read_text(encoding="utf-8"))
    manifest = verify_report_manifest(run)
    latest = json.loads(Path(plan.latest_path).read_text(encoding="utf-8"))
    assert manifest.cluster_summary_semantic_digest == summary_record["summary_semantic_digest"]
    assert manifest.cluster_candidate_count == 1
    assert manifest.cluster_evidence_record_count == 1
    assert manifest.cluster_unique_evidence_count == 1
    assert manifest.cluster_duplicate_alias_count == 0
    assert manifest.cluster_available_count == 1
    assert manifest.cluster_unavailable_count == 0
    assert latest["cluster_summary_semantic_digest"] == manifest.cluster_summary_semantic_digest
    assert latest["cluster_candidate_count"] == 1
    assert publication.cluster_summary_semantic_digest == manifest.cluster_summary_semantic_digest
    assert publication.cluster_candidate_count == 1


def test_phase33_cluster_summary_tamper_is_rejected(tmp_path: Path) -> None:
    plan, snapshot = _snapshot(tmp_path, {"sample.exe": _record(_available_retrieval())})
    publish_scan_report_set(snapshot)
    summary_path = Path(plan.run_path) / "cluster_findings_summary.json"
    record = json.loads(summary_path.read_text(encoding="utf-8"))
    record["counts"]["candidate_count"] = 99
    summary_path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    with pytest.raises(RuntimeError, match="report_manifest_file_mismatch"):
        verify_report_manifest(plan.run_path)


def test_phase33_invalid_present_cluster_evidence_blocks_activation(tmp_path: Path) -> None:
    invalid = unavailable_attack_candidate_retrieval("no_cluster").to_record()
    invalid["schema_version"] = "invalid"
    plan, snapshot = _snapshot(
        tmp_path,
        {"sample.exe": {"model_evidence": {"attack_candidate_retrieval": invalid}}},
    )
    with pytest.raises(RuntimeError, match="cluster_summary_source_schema_invalid"):
        publish_scan_report_set(snapshot)
    assert Path(plan.staging_path).is_dir()
    assert not Path(plan.run_path).exists()
    assert not Path(plan.latest_path).exists()


def test_phase33_projector_and_contract_have_single_canonical_owners() -> None:
    source = Path("Virus_Scan/publication/cluster_summary.py").read_text(encoding="utf-8")
    assert "Virus_Scan.models.clustering" not in source
    assert "Virus_Scan.detection.attack.candidate_retrieval" not in source
    assert "Virus_Scan.detection.attack.mapping" not in source
    assert "evaluate_chain" not in source
    assert "ThreadPoolExecutor" not in source
    assert "ProcessPoolExecutor" not in source
    assert ".write_text(" not in source
    assert ".write_bytes(" not in source

    definitions = []
    for path in Path("Virus_Scan").rglob("*.py"):
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if 'ATTACK_CANDIDATE_RETRIEVAL_SCHEMA_VERSION = "stage2636_11020_attack_candidate_retrieval_v1"' in text:
            definitions.append(path.as_posix())
    assert definitions == ["Virus_Scan/detection/api/attack_candidate_retrieval_contracts.py"]
    assert ATTACK_CANDIDATE_RETRIEVAL_SCHEMA_VERSION == "stage2636_11020_attack_candidate_retrieval_v1"
    assert ATTACK_CANDIDATE_RETRIEVAL_VERSION == "stage2636_11020_phase24_candidate_retriever_v1"
