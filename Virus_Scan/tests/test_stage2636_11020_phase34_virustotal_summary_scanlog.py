from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from Virus_Scan.core.logging import configure_single_parent_log, release_single_parent_log
from Virus_Scan.publication.report_set import (
    build_scan_publication_snapshot,
    publish_scan_report_set,
    verify_report_manifest,
)
from Virus_Scan.publication.virustotal_summary import (
    build_virustotal_findings_summary,
    render_virustotal_publication,
)
from Virus_Scan.runtime.resource_paths import build_scan_log_output_plan, resource_root_snapshot_from_program_root
from Virus_Scan.virustotal.config import VirusTotalConfig, config_toml
from Virus_Scan.virustotal.contracts import VirusTotalReportingResult
from Virus_Scan.virustotal.reporting import run_virustotal_reporting
from Virus_Scan.virustotal.runtime import initialize_virustotal_runtime


_SCAN_ID = "scan-00000000000000000034-aaaaaaaaaaaaaaaaaaaa"
_SNAPSHOT_DIGEST = "b" * 64
_CONTENT_SHA = "c" * 64
_CONFIG_DIGEST = "d" * 64


def _local_results(*, verdict: str = "high_confidence", score: float = 92.0) -> dict[str, object]:
    return {
        "sample.py": {
            "sha256": _CONTENT_SHA,
            "classification": verdict,
            "score": score,
            "tags": ("physical_reference",),
        }
    }


def _complete_source_row(*, full_response: object | None = None) -> dict[str, object]:
    row: dict[str, object] = {
        "path": "sample.py",
        "content_sha256": _CONTENT_SHA,
        "umige_score": 92.0,
        "umige_risk": "high_confidence",
        "selection_reason": "local_high_or_malicious",
        "submitted": True,
        "skipped": False,
        "reporting_status": "complete",
        "vt_completed": True,
        "analysis_id": "analysis-34",
        "permalink": "https://www.virustotal.com/gui/file/" + _CONTENT_SHA,
        "summary": {
            "status": "completed",
            "malicious": 7,
            "suspicious": 1,
            "harmless": 50,
            "undetected": 10,
            "timeout": 0,
            "failure": 0,
            "type_unsupported": 0,
        },
    }
    if full_response is not None:
        row["full_response"] = full_response
    return row


def _complete_result(*, include_full_response: bool = False) -> VirusTotalReportingResult:
    return VirusTotalReportingResult(
        status="complete",
        config_digest=_CONFIG_DIGEST,
        config_path="VirusTotal/virustotal_config.toml",
        api_key_environment_variable="VIRUSTOTAL_API_KEY",
        selected_count=1,
        submitted_count=1,
        skipped_count=0,
        results=(_complete_source_row(full_response={"data": {"id": "analysis-34"}}),),
        errors=(),
        write_normalized_results=True,
        include_full_response=include_full_response,
    )


def test_phase34_complete_projection_is_external_only_and_deterministic() -> None:
    local_results = _local_results()
    before = copy.deepcopy(local_results)
    result = _complete_result()

    first = build_virustotal_findings_summary(
        scan_id=_SCAN_ID,
        snapshot_semantic_digest=_SNAPSHOT_DIGEST,
        local_results=local_results,
        virustotal_result=result,
    )
    second = build_virustotal_findings_summary(
        scan_id=_SCAN_ID,
        snapshot_semantic_digest=_SNAPSHOT_DIGEST,
        local_results=local_results,
        virustotal_result=result,
    )

    assert local_results == before
    assert first.semantic_digest == second.semantic_digest
    assert first.status == "complete"
    assert first.counts_record() == {
        "finding_count": 1,
        "selected_count": 1,
        "submitted_count": 1,
        "skipped_count": 0,
        "complete_count": 1,
        "incomplete_count": 0,
        "malicious_engine_count": 7,
        "suspicious_engine_count": 1,
        "disagreement_count": 0,
    }
    row = first.rows[0]
    assert row.content_sha256 == _CONTENT_SHA
    assert row.local_verdict == "high_confidence"
    assert row.local_score == 92.0
    assert row.analysis_status == "completed"
    assert row.engine_total == 68
    assert row.disagreement_state == "agreement_positive"
    assert row.evidence_authority == "external_corroboration"
    assert row.local_result_mutated is False
    policy = first.to_record()["projection_policy"]
    assert policy["local_score_mutation"] is False
    assert policy["local_verdict_mutation"] is False
    assert policy["tag_mutation"] is False
    assert policy["chain_mutation"] is False
    assert policy["mitre_mutation"] is False
    assert policy["learning_mutation"] is False


def test_phase34_unconfigured_projection_is_explicit_unknown_not_negative() -> None:
    result = VirusTotalReportingResult(
        status="unconfigured",
        config_digest=_CONFIG_DIGEST,
        config_path="VirusTotal/virustotal_config.toml",
        api_key_environment_variable="VIRUSTOTAL_API_KEY",
    )
    summary = build_virustotal_findings_summary(
        scan_id=_SCAN_ID,
        snapshot_semantic_digest=_SNAPSHOT_DIGEST,
        local_results={},
        virustotal_result=result,
    )

    record = summary.to_record()
    assert record["status"] == "unconfigured"
    assert record["counts"]["finding_count"] == 0
    assert record["projection_policy"]["unknown_is_negative"] is False
    assert record["evidence_authority"] == "external_corroboration"
    assert record["local_result_mutated"] is False


def test_phase34_full_response_is_omitted_by_default_and_bounded_by_explicit_policy() -> None:
    default_summary = build_virustotal_findings_summary(
        scan_id=_SCAN_ID,
        snapshot_semantic_digest=_SNAPSHOT_DIGEST,
        local_results=_local_results(),
        virustotal_result=_complete_result(include_full_response=False),
    )
    enabled_summary = build_virustotal_findings_summary(
        scan_id=_SCAN_ID,
        snapshot_semantic_digest=_SNAPSHOT_DIGEST,
        local_results=_local_results(),
        virustotal_result=_complete_result(include_full_response=True),
    )

    default_raw = default_summary.normalized_results_record()["results"][0]
    enabled_raw = enabled_summary.normalized_results_record()["results"][0]
    assert "full_response" not in default_raw
    assert enabled_raw["full_response"] == {"data": {"id": "analysis-34"}}
    assert "full_response" not in enabled_summary.rows[0].summary_record()


def test_phase34_report_set_owns_raw_and_summary_files_and_manifest_reconciliation(tmp_path: Path) -> None:
    plan = build_scan_log_output_plan(scan_id=_SCAN_ID, root=tmp_path / "Scan Logs")
    staging = Path(plan.staging_path)
    staging.mkdir(parents=True)
    local_results = _local_results()
    (staging / "scan_results.json").write_text(json.dumps(local_results, sort_keys=True), encoding="utf-8")
    (staging / "scanlog").write_text("[SCAN] complete\n", encoding="utf-8")
    snapshot = build_scan_publication_snapshot(
        output_plan=plan,
        local_results=local_results,
        ledger_summary={"record_count": 1, "ledger_digest": "e" * 64},
        virustotal_result=_complete_result(),
        persistence_status={"ok": True},
        max_score=92.0,
        elapsed_sec=1.0,
        scan_had_error=False,
        session_generation_id="f" * 64,
    )

    published = publish_scan_report_set(snapshot)
    manifest = verify_report_manifest(plan.run_path)
    run = Path(plan.run_path)
    expected_names = {
        "virustotal_results.json",
        "virustotal_findings_summary.json",
        "virustotal_findings_summary.md",
        "virustotal_findings_summary.csv",
    }
    assert expected_names.issubset({path.name for path in run.iterdir()})
    assert manifest.virustotal_status == "complete"
    assert manifest.virustotal_config_digest == _CONFIG_DIGEST
    assert manifest.virustotal_finding_count == 1
    assert manifest.virustotal_selected_count == 1
    assert manifest.virustotal_submitted_count == 1
    assert manifest.virustotal_skipped_count == 0
    assert manifest.virustotal_disagreement_count == 0
    assert published.virustotal_status == "complete"
    assert published.virustotal_finding_count == 1
    summary_record = json.loads((run / "virustotal_findings_summary.json").read_text(encoding="utf-8"))
    raw_record = json.loads((run / "virustotal_results.json").read_text(encoding="utf-8"))
    assert summary_record["summary_semantic_digest"] == manifest.virustotal_summary_semantic_digest
    assert raw_record["status"] == "complete"
    assert raw_record["evidence_authority"] == "external_corroboration"
    assert raw_record["local_result_mutated"] is False


def test_phase34_report_manifest_rejects_tampered_vt_projection(tmp_path: Path) -> None:
    plan = build_scan_log_output_plan(scan_id=_SCAN_ID, root=tmp_path / "Scan Logs")
    staging = Path(plan.staging_path)
    staging.mkdir(parents=True)
    local_results = _local_results()
    (staging / "scan_results.json").write_text(json.dumps(local_results, sort_keys=True), encoding="utf-8")
    (staging / "scanlog").write_text("[SCAN] complete\n", encoding="utf-8")
    snapshot = build_scan_publication_snapshot(
        output_plan=plan,
        local_results=local_results,
        ledger_summary={"record_count": 1},
        virustotal_result=_complete_result(),
        persistence_status={"ok": True},
        max_score=92.0,
        elapsed_sec=1.0,
        scan_had_error=False,
        session_generation_id="f" * 64,
    )
    publish_scan_report_set(snapshot)
    raw = Path(plan.run_path) / "virustotal_results.json"
    raw.write_text("{}\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="report_manifest_file_mismatch:virustotal_results.json"):
        verify_report_manifest(plan.run_path)


def test_phase34_parent_scanlog_receives_typed_vt_event_without_local_mutation(tmp_path: Path) -> None:
    roots = resource_root_snapshot_from_program_root(tmp_path)
    config_path = Path(roots.virustotal_root) / "virustotal_config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(config_toml(VirusTotalConfig(enabled=False, print_to_cli=False)), encoding="utf-8")
    vt_runtime = initialize_virustotal_runtime(roots)
    log_path = tmp_path / "scanlog"
    configure_single_parent_log(log_path)
    local_results = _local_results(verdict="benign_clean", score=0.0)
    before = copy.deepcopy(local_results)
    try:
        result = run_virustotal_reporting(local_results, vt_runtime)
    finally:
        assert release_single_parent_log(log_path) is True

    assert result.status == "disabled"
    assert result.evidence_authority == "external_corroboration"
    assert result.local_result_mutated is False
    assert local_results == before
    lines = log_path.read_text(encoding="utf-8").splitlines()
    vt_lines = [line for line in lines if "[VT] " in line]
    assert vt_lines
    payload = json.loads(vt_lines[-1].split("[VT] ", 1)[1])
    assert payload["event"] == "summary"
    assert payload["status"] == "disabled"
    assert payload["evidence_authority"] == "external_corroboration"
    assert payload["local_result_mutated"] is False


def test_phase34_source_has_one_parent_publication_and_logging_owner() -> None:
    vt_source = Path("Virus_Scan/virustotal/reporting.py").read_text(encoding="utf-8")
    generic_summary = Path("Virus_Scan/reporting/summary.py").read_text(encoding="utf-8")
    report_set_source = Path("Virus_Scan/publication/report_set.py").read_text(encoding="utf-8")
    runtime_config = Path("Virus_Scan/runtime/config.py").read_text(encoding="utf-8")
    lifecycle = Path("Virus_Scan/orchestration/lifecycle.py").read_text(encoding="utf-8")

    assert "print(" not in vt_source
    assert "write_reporting_json" not in vt_source
    assert "_write_result" not in vt_source
    assert "_merge_previous" not in vt_source
    assert "vt_print_summary" not in generic_summary
    assert "virustotal_results.json" in report_set_source
    assert "virustotal_findings_summary.json" in report_set_source
    assert "emit_parent_scan_log_event" in vt_source
    assert "vt_output" not in runtime_config
    assert "preserve_virustotal_results" not in runtime_config
    assert "vt_output" not in lifecycle
    assert "preserve_virustotal_results" not in lifecycle


def test_phase34_rendered_report_set_contains_all_vt_formats_once() -> None:
    summary = build_virustotal_findings_summary(
        scan_id=_SCAN_ID,
        snapshot_semantic_digest=_SNAPSHOT_DIGEST,
        local_results=_local_results(),
        virustotal_result=_complete_result(),
    )
    rendered = render_virustotal_publication(summary)
    names = tuple(name for name, _payload in rendered)
    assert names == (
        "virustotal_results.json",
        "virustotal_findings_summary.json",
        "virustotal_findings_summary.md",
        "virustotal_findings_summary.csv",
    )
    assert len(set(names)) == len(names)
