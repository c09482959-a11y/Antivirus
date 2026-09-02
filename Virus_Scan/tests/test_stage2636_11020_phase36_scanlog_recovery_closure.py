from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from Virus_Scan.core.logging import configure_single_parent_log, release_single_parent_log
from Virus_Scan.orchestration.lifecycle import report_results
from Virus_Scan.publication.report_set import build_scan_publication_snapshot, publish_scan_report_set
from Virus_Scan.publication.scan_result_ledger import (
    FINAL_SCANLOG_EVENT_TYPES,
    ScanResultLedgerAccumulator,
    parse_scanlog_ledger,
)
from Virus_Scan.routing.context_identity import RoutingEvidenceContext, attach_routing_evidence_to_record
from Virus_Scan.runtime.resource_paths import build_scan_log_output_plan, resource_root_snapshot_from_program_root
from Virus_Scan.stress.run_verifier import verify_final_scanlog_events
from Virus_Scan.virustotal.config import VirusTotalConfig, config_toml
from Virus_Scan.virustotal.runtime import initialize_virustotal_runtime
from Virus_Scan.virustotal.contracts import VirusTotalReportingResult

_SCAN_ID = "scan-00000000000000000036-cccccccccccccccccccc"


class _Runtime:
    parent_cli = True

    def __init__(self) -> None:
        self.scan_started_at = time.time()
        self.values: dict[str, object] = {}

    def get(self, name: str, default: object = None) -> object:
        return self.values.get(name, default)

    def set(self, name: str, value: object) -> None:
        self.values[name] = value


def _run_lifecycle(tmp_path: Path):
    plan = build_scan_log_output_plan(scan_id=_SCAN_ID, root=tmp_path / "Scan Logs")
    Path(plan.staging_path).mkdir(parents=True)
    config_path = tmp_path / "VirusTotal" / "virustotal_config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(config_toml(VirusTotalConfig(enabled=False, print_to_cli=False)), encoding="utf-8")
    log_path = plan.staging_report_path("scanlog")
    configure_single_parent_log(log_path)

    sample = tmp_path / "sample.py"
    sample.write_text("print('phase36 safe')\n", encoding="utf-8")
    record = {
        "file": sample.as_posix(),
        "score": 0.0,
        "class": "benign_clean",
        "classification": "benign_clean",
        "tags": [],
        "profile_selection": {"active_profile": "other"},
        "scan_session_generation_id": "d" * 64,
    }
    record = attach_routing_evidence_to_record(
        record,
        sample.as_posix(),
        container_root=tmp_path,
        evidence_context=RoutingEvidenceContext.build(tmp_path),
    )
    args = SimpleNamespace(
        output=plan.staging_report_path("scan_results.json").as_posix(),
        log=log_path.as_posix(),
        scheduler="serial",
        engine="auto",
        dir=tmp_path.as_posix(),
        scan_log_output_plan=plan,
    )
    runtime = _Runtime()
    runtime.virustotal_runtime = initialize_virustotal_runtime(resource_root_snapshot_from_program_root(tmp_path))
    report_results(runtime, args, {sample.as_posix(): record}, yara_ok=False, persistence_status={"ok": True})
    return plan, runtime, log_path


def _final_events(scanlog_path: Path) -> dict[str, dict[str, object]]:
    parsed = parse_scanlog_ledger(scanlog_path.read_text(encoding="utf-8").splitlines())
    names = {
        "SCAN": "final_publication_snapshot",
        "YARA": "final_projection",
        "CHAIN": "final_projection",
        "MITRE": "final_projection",
        "CLUSTER": "final_projection",
        "VT": "final_projection",
        "SUMMARY": "combined_malicious_findings",
        "REPORT_SET": "publication_prepared",
    }
    typed = parsed["typed_events"]
    return {
        event_type: [row for row in typed[event_type] if row.get("event") == event_name][0]
        for event_type, event_name in names.items()
    }


def test_phase36_parser_understands_typed_events_without_weakening_ledger() -> None:
    accumulator = ScanResultLedgerAccumulator()
    accumulator.observe("sample", {"sample_id": "sample", "sha256": "a" * 64, "classification": "benign"})
    lines: list[str] = []
    accumulator.publish("missing.json", log_info=lines.append, persistence_status={"ok": True})
    lines.extend((
        '[VT] {"event":"final_projection","scan_id":"scan","snapshot_semantic_digest":"' + "b" * 64 + '"}',
        '[SUMMARY] {"event":"combined_malicious_findings","scan_id":"scan","snapshot_semantic_digest":"' + "b" * 64 + '"}',
        '[YARA] not-json',
    ))
    parsed = parse_scanlog_ledger(lines)
    assert len(parsed["results"]) == 1
    assert len(parsed["summaries"]) == 1
    assert parsed["typed_events"]["VT"][0]["event"] == "final_projection"
    assert parsed["typed_events"]["SUMMARY"][0]["event"] == "combined_malicious_findings"
    assert parsed["malformed_typed_events"] == ("YARA",)


def test_phase36_lifecycle_emits_one_final_event_per_required_type_and_closes_log_before_rename(tmp_path: Path) -> None:
    plan, _runtime, original_log_path = _run_lifecycle(tmp_path)
    final_log = Path(plan.run_path) / "scanlog"
    parsed = parse_scanlog_ledger(final_log.read_text(encoding="utf-8").splitlines())
    assert len(parsed["results"]) == 1
    assert len(parsed["summaries"]) == 1
    assert parsed["malformed_typed_events"] == ()
    finals = _final_events(final_log)
    assert tuple(sorted(finals)) == tuple(sorted(FINAL_SCANLOG_EVENT_TYPES))
    assert verify_final_scanlog_events(final_log) == ()
    # The report-set owner already flushed/closed the staging handle before directory rename.
    assert release_single_parent_log(original_log_path) is False


def test_phase36_final_scanlog_events_reconcile_manifest_and_latest_activation(tmp_path: Path) -> None:
    plan, runtime, _log_path = _run_lifecycle(tmp_path)
    run = Path(plan.run_path)
    manifest = json.loads((run / "report_manifest.json").read_text(encoding="utf-8"))
    latest = json.loads(Path(plan.latest_path).read_text(encoding="utf-8"))
    finals = _final_events(run / "scanlog")

    common_identity = {(row["scan_id"], row["snapshot_semantic_digest"]) for row in finals.values()}
    assert common_identity == {(_SCAN_ID, manifest["snapshot_semantic_digest"])}
    assert finals["YARA"]["summary_semantic_digest"] == manifest["yara_summary_semantic_digest"]
    assert finals["CHAIN"]["summary_semantic_digest"] == manifest["chain_summary_semantic_digest"]
    assert finals["MITRE"]["summary_semantic_digest"] == manifest["mitre_summary_semantic_digest"]
    assert finals["CLUSTER"]["summary_semantic_digest"] == manifest["cluster_summary_semantic_digest"]
    assert finals["VT"]["summary_semantic_digest"] == manifest["virustotal_summary_semantic_digest"]
    assert finals["SUMMARY"]["summary_semantic_digest"] == manifest["malicious_summary_semantic_digest"]
    assert finals["SUMMARY"]["combined_score"] is None
    assert finals["REPORT_SET"]["completion_state"] == "prepared_not_activated"
    assert finals["REPORT_SET"]["activation_record_owner"] == "latest.json"
    assert latest["completion_state"] == "complete"
    assert latest["scan_id"] == _SCAN_ID
    assert latest["manifest_self_digest"] == manifest["manifest_self_digest"]
    assert runtime.values["SCAN_PUBLICATION_RESULT"]["manifest_self_digest"] == manifest["manifest_self_digest"]


def test_phase36_prepared_report_set_failure_preserves_staging_and_prior_latest(tmp_path: Path) -> None:
    plan = build_scan_log_output_plan(scan_id=_SCAN_ID, root=tmp_path / "Scan Logs")
    staging = Path(plan.staging_path)
    staging.mkdir(parents=True)
    local = {"sample.py": {"sha256": "a" * 64, "classification": "benign", "score": 0.0}}
    (staging / "scan_results.json").write_text(json.dumps(local), encoding="utf-8")
    log_path = plan.staging_report_path("scanlog")
    configure_single_parent_log(log_path)
    logging.info("phase36 before prepared publication")
    (staging / "unknown-runtime-file.tmp").write_text("block activation", encoding="utf-8")
    latest = Path(plan.latest_path)
    latest.parent.mkdir(parents=True, exist_ok=True)
    prior = {"schema_version": "prior", "scan_id": "prior"}
    latest.write_text(json.dumps(prior), encoding="utf-8")
    snapshot = build_scan_publication_snapshot(
        output_plan=plan,
        local_results=local,
        ledger_summary={"record_count": 1, "ledger_digest": "b" * 64},
        virustotal_result=VirusTotalReportingResult(
            status="unconfigured",
            config_digest="c" * 64,
            config_path="VirusTotal/virustotal_config.toml",
            api_key_environment_variable="VIRUSTOTAL_API_KEY",
        ),
        persistence_status={"ok": True},
        max_score=0.0,
        elapsed_sec=1.0,
        scan_had_error=False,
        session_generation_id="d" * 64,
    )

    with pytest.raises(RuntimeError, match="scan_report_staging_unknown_files"):
        publish_scan_report_set(snapshot)
    assert staging.is_dir()
    assert not Path(plan.run_path).exists()
    assert json.loads(latest.read_text(encoding="utf-8")) == prior
    assert release_single_parent_log(log_path) is False
    assert verify_final_scanlog_events(log_path) == ()
    parsed = parse_scanlog_ledger(log_path.read_text(encoding="utf-8").splitlines())
    report_set = [row for row in parsed["typed_events"]["REPORT_SET"] if row.get("event") == "publication_prepared"]
    assert len(report_set) == 1
    assert report_set[0]["completion_state"] == "prepared_not_activated"


def test_phase36_verifier_rejects_malformed_or_missing_final_event_contract(tmp_path: Path) -> None:
    path = tmp_path / "scanlog"
    path.write_text('[SCAN] {"event":"final_publication_snapshot"}\n[YARA] not-json\n', encoding="utf-8")
    errors = verify_final_scanlog_events(path)
    assert any(error.startswith("scanlog_typed_event_malformed:YARA") for error in errors)
    assert any(error.startswith("scanlog_final_event_count_invalid:REPORT_SET") for error in errors)


def test_phase36_source_has_one_parent_log_close_and_event_owner() -> None:
    lifecycle = Path("Virus_Scan/orchestration/lifecycle.py").read_text(encoding="utf-8")
    report_set = Path("Virus_Scan/publication/report_set.py").read_text(encoding="utf-8")
    ledger = Path("Virus_Scan/publication/scan_result_ledger.py").read_text(encoding="utf-8")

    assert "release_single_parent_log" not in lifecycle
    assert "emit_parent_scan_log_event" in report_set
    assert "release_single_parent_log" in report_set
    assert report_set.count('render_yara_findings_summary(yara_summary)') == 1
    assert report_set.count('render_chain_findings_summary(chain_summary)') == 1
    assert report_set.count('render_mitre_findings_summary(mitre_summary)') == 1
    assert report_set.count('render_cluster_findings_summary(cluster_summary)') == 1
    assert report_set.count('render_virustotal_publication(virustotal_summary)') == 1
    assert report_set.count('render_malicious_findings_summary(malicious_summary)') == 1
    for event_type in FINAL_SCANLOG_EVENT_TYPES:
        assert ('emit_parent_scan_log_event("' + event_type + '"') in report_set
    assert "typed_events" in ledger
