from __future__ import annotations

import json
from pathlib import Path

import pytest

from Virus_Scan.contracts.detection_observation import ObservationSourceLocation
from Virus_Scan.contracts.yara_hits import YaraHit, YaraRuleIdentity, YaraScanResult
from Virus_Scan.publication.json_finalization.success_fields import compact_success_analysis_fields
from Virus_Scan.publication.report_set import (
    build_scan_publication_snapshot,
    publish_scan_report_set,
    verify_report_manifest,
)
from Virus_Scan.publication.yara_summary import build_yara_findings_summary
from Virus_Scan.runtime.resource_paths import build_scan_log_output_plan
from Virus_Scan.virustotal.contracts import VirusTotalReportingResult


def _yara_result(*, target_digit: str = "6", scan_digit: str = "7", truncated: bool = False) -> YaraScanResult:
    rule = YaraRuleIdentity(
        package_kind="core",
        rule_source_digest="1" * 64,
        compiled_cache_digest="2" * 64,
        rule_catalog_digest="3" * 64,
        source_member="rules/example.yar",
        compiler_namespace="core",
        rule_name="ExampleRule",
        metadata_id="RULE-1",
        logic_hash="4" * 64,
        semantic_metadata_digest="5" * 64,
        rule_tags=("credential",),
    )
    hit = YaraHit(
        rule_identity=rule,
        root_observation_id="obs_" + "a" * 64,
        integrity_status="verified",
        source_trust="official_verified",
        release_id=509,
        release_tag="v5.0.9",
        compile_policy_version="yara_compile_policy_v1",
        artifact_identity="sha256:" + target_digit * 64,
        source_location=ObservationSourceLocation(
            location_type="file",
            locator="sample.bin",
            byte_offset=12,
            byte_length=8,
        ),
    )
    return YaraScanResult(
        status="truncated" if truncated else "complete",
        scan_pass_id="yscan_" + scan_digit * 64,
        physical_target_identity="sha256:" + target_digit * 64,
        package_kind="core",
        rule_source_digest="1" * 64,
        compiled_cache_digest="2" * 64,
        rule_catalog_digest="3" * 64,
        hits=(hit,),
        total_match_count=2 if truncated else 1,
        retained_match_count=1,
        duplicate_match_count=0,
        truncated_match_count=1 if truncated else 0,
        archive_member_count=1,
        scanned_member_count=1,
        failed_member_count=0,
        failure_reasons=("yara_match_limit_reached",) if truncated else (),
    )


def _snapshot(tmp_path: Path, local_results: dict[str, object]):
    plan = build_scan_log_output_plan(
        scan_id="scan-00000000000000000030-aaaaaaaaaaaaaaaaaaaa",
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


def test_phase30_projection_preserves_exact_physical_yara_identity() -> None:
    result = _yara_result(truncated=True)
    summary = build_yara_findings_summary(
        scan_id="scan-30",
        snapshot_semantic_digest="8" * 64,
        local_results={
            "sample.bin": {
                "yara_evidence": result.to_record(),
                "tags": ["credential_access"],
                "chains": ["chain-credential"],
                "attack_intelligence": {"technique_ids": ["T1003.001"]},
            }
        },
    )

    assert summary.one_scan_reconciled is True
    assert summary.counts_record()["total_match_count"] == 2
    assert summary.counts_record()["retained_match_count"] == 1
    assert summary.counts_record()["truncated_match_count"] == 1
    row = summary.finding_rows[0]
    hit = result.hits[0]
    assert row.rule_identity_digest == hit.rule_identity.digest
    assert row.scan_result_schema_version == result.schema_version
    assert row.rule_identity_schema_version == hit.rule_identity.schema_version
    assert row.hit_schema_version == hit.schema_version
    assert row.root_observation_id == hit.root_observation_id
    assert row.artifact_identity == hit.artifact_identity
    assert row.verified is True
    assert row.rule_mapping_eligible is True
    assert row.downstream_tag_references == ("credential_access",)
    assert row.downstream_chain_references == ("chain-credential",)
    assert row.downstream_mitre_references == ("T1003.001",)
    assert row.eligible_for_probability is False
    assert row.eligible_for_attack_confirmation is False


def test_phase30_duplicate_path_aliases_do_not_duplicate_physical_finding() -> None:
    record = {"yara_evidence": _yara_result().to_record()}
    summary = build_yara_findings_summary(
        scan_id="scan-30",
        snapshot_semantic_digest="8" * 64,
        local_results={"first.bin": record, "alias.bin": record},
    )
    assert summary.source_record_count == 2
    assert summary.duplicate_alias_count == 1
    assert len(summary.scan_rows) == 1
    assert len(summary.finding_rows) == 1
    assert summary.scan_rows[0].record_keys == ("alias.bin", "first.bin")


def test_phase30_conflicting_results_for_same_physical_target_fail_closed() -> None:
    first = _yara_result(scan_digit="7")
    second = _yara_result(scan_digit="8")
    with pytest.raises(RuntimeError, match="yara_summary_physical_target_scan_conflict"):
        build_yara_findings_summary(
            scan_id="scan-30",
            snapshot_semantic_digest="8" * 64,
            local_results={
                "first.bin": {"yara_evidence": first.to_record()},
                "second.bin": {"yara_evidence": second.to_record()},
            },
        )


def test_phase30_compact_finalization_preserves_exact_yara_evidence() -> None:
    result = _yara_result()
    fields = compact_success_analysis_fields(
        {"yara_evidence": result.to_record(), "yara_hits": ["ExampleRule"]},
        {"explanation": {}, "reasons": []},
    )
    assert fields["yara_evidence"] == result.to_record()
    assert fields["yara_hits"] == ["ExampleRule"]


def test_phase30_parent_transaction_publishes_and_manifests_all_yara_formats(tmp_path: Path) -> None:
    result = _yara_result()
    local_results = {
        "sample.bin": {
            "sha256": "6" * 64,
            "classification": "benign_clean",
            "score": 0.0,
            "yara_evidence": result.to_record(),
        }
    }
    plan, snapshot = _snapshot(tmp_path, local_results)
    publication = publish_scan_report_set(snapshot)

    run = Path(plan.run_path)
    for name in ("yara_findings_summary.json", "yara_findings_summary.md", "yara_findings_summary.csv"):
        assert (run / name).is_file()
    summary_record = json.loads((run / "yara_findings_summary.json").read_text(encoding="utf-8"))
    manifest = verify_report_manifest(run)
    latest = json.loads(Path(plan.latest_path).read_text(encoding="utf-8"))
    assert manifest.yara_summary_semantic_digest == summary_record["summary_semantic_digest"]
    assert manifest.yara_scan_count == 1
    assert manifest.yara_finding_count == 1
    assert manifest.yara_total_match_count == 1
    assert manifest.yara_retained_match_count == 1
    assert manifest.yara_one_scan_reconciled is True
    assert latest["yara_summary_semantic_digest"] == manifest.yara_summary_semantic_digest
    assert latest["yara_finding_count"] == 1
    assert publication.yara_summary_semantic_digest == manifest.yara_summary_semantic_digest


def test_phase30_yara_summary_tamper_is_rejected(tmp_path: Path) -> None:
    plan, snapshot = _snapshot(
        tmp_path,
        {"sample.bin": {"sha256": "6" * 64, "yara_evidence": _yara_result().to_record()}},
    )
    publish_scan_report_set(snapshot)
    summary_path = Path(plan.run_path) / "yara_findings_summary.json"
    record = json.loads(summary_path.read_text(encoding="utf-8"))
    record["counts"]["finding_count"] = 99
    summary_path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    with pytest.raises(RuntimeError, match="report_manifest_file_mismatch"):
        verify_report_manifest(plan.run_path)


def test_phase30_invalid_present_yara_evidence_blocks_activation(tmp_path: Path) -> None:
    plan, snapshot = _snapshot(tmp_path, {"sample.bin": {"yara_evidence": {"status": "complete"}}})
    with pytest.raises(RuntimeError, match="yara_summary_source_invalid"):
        publish_scan_report_set(snapshot)
    assert Path(plan.staging_path).is_dir()
    assert not Path(plan.run_path).exists()
    assert not Path(plan.latest_path).exists()


def test_phase30_projector_has_no_scanner_or_filesystem_writer_owner() -> None:
    source = Path("Virus_Scan/publication/yara_summary.py").read_text(encoding="utf-8")
    assert "Virus_Scan.yara" not in source
    assert "scan_file" not in source
    assert "ThreadPoolExecutor" not in source
    assert "ProcessPoolExecutor" not in source
    assert ".write_text(" not in source
    assert ".write_bytes(" not in source
