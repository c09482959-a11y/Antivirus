from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from Virus_Scan.publication.chain_summary import build_chain_findings_summary
from Virus_Scan.publication.cluster_summary import build_cluster_findings_summary
from Virus_Scan.publication.malicious_summary import (
    build_malicious_findings_summary,
    render_malicious_findings_summary,
)
from Virus_Scan.publication.mitre_summary import build_mitre_findings_summary
from Virus_Scan.publication.report_set import (
    build_scan_publication_snapshot,
    publish_scan_report_set,
    verify_report_manifest,
)
from Virus_Scan.publication.virustotal_summary import build_virustotal_findings_summary
from Virus_Scan.publication.yara_summary import build_yara_findings_summary
from Virus_Scan.runtime.resource_paths import build_scan_log_output_plan
from Virus_Scan.virustotal.contracts import VirusTotalReportingResult

_SCAN_ID = "scan-00000000000000000035-bbbbbbbbbbbbbbbbbbbb"
_SNAPSHOT_DIGEST = "a" * 64
_SHA_A = "1" * 64
_SHA_B = "2" * 64
_CONFIG_DIGEST = "3" * 64


def _local_results() -> dict[str, object]:
    return {
        "first.py": {"sha256": _SHA_A, "classification": "malicious", "score": 91.0},
        "alias.py": {"sha256": _SHA_A, "classification": "malicious", "score": 91.0},
        "vt-only.py": {"sha256": _SHA_B, "classification": "benign", "score": 2.0},
    }


def _vt_source_row() -> dict[str, object]:
    return {
        "path": "vt-only.py",
        "content_sha256": _SHA_B,
        "umige_score": 2.0,
        "umige_risk": "benign",
        "selection_reason": "explicit_phase35_test_selection",
        "submitted": True,
        "skipped": False,
        "reporting_status": "complete",
        "vt_completed": True,
        "analysis_id": "analysis-phase35",
        "permalink": "https://www.virustotal.com/gui/file/" + _SHA_B,
        "summary": {
            "status": "completed",
            "malicious": 5,
            "suspicious": 1,
            "harmless": 55,
            "undetected": 9,
            "timeout": 0,
            "failure": 0,
            "type_unsupported": 0,
        },
    }


def _vt_result(*, complete: bool = True) -> VirusTotalReportingResult:
    if complete:
        return VirusTotalReportingResult(
            status="complete",
            config_digest=_CONFIG_DIGEST,
            config_path="VirusTotal/virustotal_config.toml",
            api_key_environment_variable="VIRUSTOTAL_API_KEY",
            selected_count=1,
            submitted_count=1,
            skipped_count=0,
            results=(_vt_source_row(),),
            errors=(),
        )
    return VirusTotalReportingResult(
        status="unconfigured",
        config_digest=_CONFIG_DIGEST,
        config_path="VirusTotal/virustotal_config.toml",
        api_key_environment_variable="VIRUSTOTAL_API_KEY",
    )


def _source_summaries(local_results: dict[str, object], *, vt_complete: bool = True):
    yara = build_yara_findings_summary(
        scan_id=_SCAN_ID,
        snapshot_semantic_digest=_SNAPSHOT_DIGEST,
        local_results=local_results,
    )
    chain = build_chain_findings_summary(
        scan_id=_SCAN_ID,
        snapshot_semantic_digest=_SNAPSHOT_DIGEST,
        local_results=local_results,
    )
    mitre = build_mitre_findings_summary(
        scan_id=_SCAN_ID,
        snapshot_semantic_digest=_SNAPSHOT_DIGEST,
        local_results=local_results,
    )
    cluster = build_cluster_findings_summary(
        scan_id=_SCAN_ID,
        snapshot_semantic_digest=_SNAPSHOT_DIGEST,
        local_results=local_results,
    )
    vt = build_virustotal_findings_summary(
        scan_id=_SCAN_ID,
        snapshot_semantic_digest=_SNAPSHOT_DIGEST,
        local_results=local_results,
        virustotal_result=_vt_result(complete=vt_complete),
    )
    return yara, chain, mitre, cluster, vt


def _combined(local_results: dict[str, object], *, vt_complete: bool = True):
    yara, chain, mitre, cluster, vt = _source_summaries(local_results, vt_complete=vt_complete)
    return build_malicious_findings_summary(
        scan_id=_SCAN_ID,
        snapshot_semantic_digest=_SNAPSHOT_DIGEST,
        local_results=local_results,
        yara_summary=yara,
        chain_summary=chain,
        mitre_summary=mitre,
        cluster_summary=cluster,
        virustotal_summary=vt,
    )


def test_phase35_combined_summary_deduplicates_aliases_and_preserves_authority_boundaries() -> None:
    local_results = _local_results()
    before = copy.deepcopy(local_results)
    summary = _combined(local_results)

    assert local_results == before
    counts = summary.counts_record()
    assert counts["source_record_count"] == 3
    assert counts["identified_record_count"] == 3
    assert counts["unique_identity_count"] == 2
    assert counts["duplicate_alias_count"] == 1
    assert counts["finding_count"] == 2
    assert counts["local_malicious_count"] == 1
    assert counts["external_or_context_only_count"] == 1
    assert counts["virustotal_positive_count"] == 1
    assert counts["disagreement_count"] == 1

    by_sha = {row.content_sha256: row for row in summary.rows}
    local_row = by_sha[_SHA_A]
    assert local_row.record_keys == ("alias.py", "first.py")
    assert local_row.local_verdict == "malicious"
    assert local_row.local_score == 91.0
    assert local_row.section == "local_malicious"
    assert "local_malicious_or_high_confidence" in local_row.inclusion_reasons
    assert local_row.combined_score is None

    external_row = by_sha[_SHA_B]
    assert external_row.record_keys == ("vt-only.py",)
    assert external_row.local_verdict == "benign"
    assert external_row.local_score == 2.0
    assert external_row.section == "external_or_context_only"
    assert "virustotal_positive" in external_row.inclusion_reasons
    assert "virustotal_disagreement" in external_row.inclusion_reasons
    assert external_row.authority_classes == ("external_corroboration",)
    assert external_row.virustotal_disagreement_state == "local_nonpositive_external_positive"
    assert external_row.combined_score is None

    policy = summary.to_record()["projection_policy"]
    assert policy["cross_subsystem_index_only"] is True
    assert policy["report_time_detection"] is False
    assert policy["report_time_scoring"] is False
    assert policy["combined_score"] is None
    assert policy["unknown_is_negative"] is False
    assert policy["cluster_authority"] == "context_only"
    assert policy["virustotal_authority"] == "external_corroboration"


def test_phase35_unconfigured_external_state_does_not_turn_benign_into_a_finding() -> None:
    local_results = {"clean.py": {"sha256": _SHA_A, "classification": "benign", "score": 0.0}}
    summary = _combined(local_results, vt_complete=False)

    assert summary.rows == ()
    assert summary.counts_record()["finding_count"] == 0
    assert summary.to_record()["projection_policy"]["unknown_is_negative"] is False


def test_phase35_included_local_result_requires_content_identity_and_alias_conflicts_fail_closed() -> None:
    missing = {"bad.py": {"classification": "malicious", "score": 88.0}}
    yara, chain, mitre, cluster, vt = _source_summaries(missing, vt_complete=False)
    with pytest.raises(RuntimeError, match="malicious_summary_included_local_content_identity_missing"):
        build_malicious_findings_summary(
            scan_id=_SCAN_ID,
            snapshot_semantic_digest=_SNAPSHOT_DIGEST,
            local_results=missing,
            yara_summary=yara,
            chain_summary=chain,
            mitre_summary=mitre,
            cluster_summary=cluster,
            virustotal_summary=vt,
        )

    conflicting = {
        "a.py": {"sha256": _SHA_A, "classification": "malicious", "score": 90.0},
        "b.py": {"sha256": _SHA_A, "classification": "malicious", "score": 91.0},
    }
    yara, chain, mitre, cluster, vt = _source_summaries(conflicting, vt_complete=False)
    with pytest.raises(RuntimeError, match="malicious_summary_content_alias_local_semantic_conflict"):
        build_malicious_findings_summary(
            scan_id=_SCAN_ID,
            snapshot_semantic_digest=_SNAPSHOT_DIGEST,
            local_results=conflicting,
            yara_summary=yara,
            chain_summary=chain,
            mitre_summary=mitre,
            cluster_summary=cluster,
            virustotal_summary=vt,
        )


def test_phase35_member_identity_keeps_distinct_physical_members_separate() -> None:
    local = {
        "archive-a": {"sha256": _SHA_A, "classification": "malicious", "score": 80.0, "member_identity": "a.py"},
        "archive-b": {"sha256": _SHA_A, "classification": "malicious", "score": 80.0, "member_identity": "b.py"},
    }
    summary = _combined(local, vt_complete=False)
    assert summary.counts_record()["unique_identity_count"] == 2
    assert summary.counts_record()["duplicate_alias_count"] == 0
    assert {(row.content_sha256, row.member_identity) for row in summary.rows} == {
        (_SHA_A, "a.py"),
        (_SHA_A, "b.py"),
    }


def test_phase35_parent_report_set_publishes_and_reconciles_combined_summary(tmp_path: Path) -> None:
    plan = build_scan_log_output_plan(scan_id=_SCAN_ID, root=tmp_path / "Scan Logs")
    staging = Path(plan.staging_path)
    staging.mkdir(parents=True)
    local_results = _local_results()
    before = copy.deepcopy(local_results)
    (staging / "scan_results.json").write_text(json.dumps(local_results, sort_keys=True), encoding="utf-8")
    (staging / "scanlog").write_text("[SCAN] complete\n", encoding="utf-8")
    snapshot = build_scan_publication_snapshot(
        output_plan=plan,
        local_results=local_results,
        ledger_summary={"record_count": 3, "ledger_digest": "4" * 64},
        virustotal_result=_vt_result(),
        persistence_status={"ok": True},
        max_score=91.0,
        elapsed_sec=1.0,
        scan_had_error=False,
        session_generation_id="5" * 64,
    )

    published = publish_scan_report_set(snapshot)
    manifest = verify_report_manifest(plan.run_path)
    run = Path(plan.run_path)
    assert local_results == before
    assert {
        "malicious_findings_summary.json",
        "malicious_findings_summary.md",
        "malicious_findings_summary.csv",
    }.issubset({path.name for path in run.iterdir()})
    assert manifest.malicious_finding_count == 2
    assert manifest.malicious_local_malicious_count == 1
    assert manifest.malicious_local_suspicious_count == 0
    assert manifest.malicious_external_or_context_only_count == 1
    assert manifest.malicious_disagreement_count == 1
    assert manifest.malicious_duplicate_alias_count == 1
    assert published.malicious_summary_semantic_digest == manifest.malicious_summary_semantic_digest
    assert published.malicious_finding_count == 2
    assert published.malicious_disagreement_count == 1

    latest = json.loads(Path(plan.latest_path).read_text(encoding="utf-8"))
    assert latest["malicious_summary_semantic_digest"] == manifest.malicious_summary_semantic_digest
    assert latest["malicious_finding_count"] == 2
    assert latest["malicious_disagreement_count"] == 1
    combined = json.loads((run / "malicious_findings_summary.json").read_text(encoding="utf-8"))
    assert combined["summary_semantic_digest"] == manifest.malicious_summary_semantic_digest
    assert combined["source_summary_digests"]["virustotal"] == manifest.virustotal_summary_semantic_digest
    assert combined["source_summary_digests"]["yara"] == manifest.yara_summary_semantic_digest
    assert all(row["combined_score"] is None for row in combined["rows"])


def test_phase35_manifest_rejects_tampered_combined_summary(tmp_path: Path) -> None:
    plan = build_scan_log_output_plan(scan_id=_SCAN_ID, root=tmp_path / "Scan Logs")
    staging = Path(plan.staging_path)
    staging.mkdir(parents=True)
    local_results = _local_results()
    (staging / "scan_results.json").write_text(json.dumps(local_results, sort_keys=True), encoding="utf-8")
    (staging / "scanlog").write_text("[SCAN] complete\n", encoding="utf-8")
    snapshot = build_scan_publication_snapshot(
        output_plan=plan,
        local_results=local_results,
        ledger_summary={"record_count": 3},
        virustotal_result=_vt_result(),
        persistence_status={"ok": True},
        max_score=91.0,
        elapsed_sec=1.0,
        scan_had_error=False,
        session_generation_id="5" * 64,
    )
    publish_scan_report_set(snapshot)
    target = Path(plan.run_path) / "malicious_findings_summary.json"
    target.write_text("{}\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="report_manifest_file_mismatch:malicious_findings_summary.json"):
        verify_report_manifest(plan.run_path)


def test_phase35_projection_has_no_scanner_detector_mapper_or_independent_writer_owner() -> None:
    source = Path("Virus_Scan/publication/malicious_summary.py").read_text(encoding="utf-8")
    report_set = Path("Virus_Scan/publication/report_set.py").read_text(encoding="utf-8")

    assert "Virus_Scan.scanners" not in source
    assert "Virus_Scan.yara" not in source
    assert "Virus_Scan.attack" not in source
    assert "Virus_Scan.virustotal.client" not in source
    assert "evaluate_chain" not in source
    assert "open(" not in source
    assert "write_text(" not in source
    assert "write_bytes(" not in source
    names = tuple(name for name, _payload in render_malicious_findings_summary(_combined(_local_results())))
    assert names == (
        "malicious_findings_summary.json",
        "malicious_findings_summary.md",
        "malicious_findings_summary.csv",
    )
    for name in names:
        assert name in report_set
