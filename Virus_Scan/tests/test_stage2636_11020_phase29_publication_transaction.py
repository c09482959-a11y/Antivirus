from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from Virus_Scan.core.logging import configure_single_parent_log, release_single_parent_log
from Virus_Scan.orchestration.lifecycle import report_results
from Virus_Scan.publication.report_set import (
    LATEST_PUBLICATION_POINTER_SCHEMA_VERSION,
    REPORT_MANIFEST_SCHEMA_VERSION,
    SCAN_PUBLICATION_SNAPSHOT_SCHEMA_VERSION,
    build_scan_publication_snapshot,
    publish_scan_report_set,
    verify_report_manifest,
)
from Virus_Scan.routing.context_identity import RoutingEvidenceContext, attach_routing_evidence_to_record
from Virus_Scan.runtime.resource_paths import build_scan_log_output_plan, resource_root_snapshot_from_program_root
from Virus_Scan.virustotal.config import VirusTotalConfig, config_toml
from Virus_Scan.virustotal.runtime import initialize_virustotal_runtime
from Virus_Scan.virustotal.contracts import VirusTotalReportingResult


def _snapshot(tmp_path: Path, *, scan_id: str = "scan-00000000000000000001-aaaaaaaaaaaaaaaaaaaa"):
    root = tmp_path / "Scan Logs"
    plan = build_scan_log_output_plan(scan_id=scan_id, root=root)
    staging = Path(plan.staging_path)
    staging.mkdir(parents=True)
    (staging / "scan_results.json").write_text(
        json.dumps({"sample.py": {"classification": "benign_clean", "score": 0.0}}, sort_keys=True),
        encoding="utf-8",
    )
    (staging / "scanlog").write_text("[SCAN] complete\n", encoding="utf-8")
    vt = VirusTotalReportingResult(
        status="unconfigured",
        config_digest="b" * 64,
        config_path=(tmp_path / "VirusTotal/virustotal_config.toml").as_posix(),
        api_key_environment_variable="VIRUSTOTAL_API_KEY",
    )
    snapshot = build_scan_publication_snapshot(
        output_plan=plan,
        local_results={"sample.py": {"classification": "benign_clean", "score": 0.0}},
        ledger_summary={"record_count": 1, "ledger_digest": "c" * 64},
        virustotal_result=vt,
        persistence_status={"ok": True},
        max_score=0.0,
        elapsed_sec=1.25,
        scan_had_error=False,
        session_generation_id="a" * 64,
    )
    return plan, snapshot


def test_phase29_snapshot_is_immutable_and_semantic_digest_excludes_elapsed(tmp_path: Path) -> None:
    plan, first = _snapshot(tmp_path)
    second = build_scan_publication_snapshot(
        output_plan=plan,
        local_results={"sample.py": {"classification": "benign_clean", "score": 0.0}},
        ledger_summary={"record_count": 1, "ledger_digest": "c" * 64},
        virustotal_result=first.virustotal_result,
        persistence_status={"ok": True},
        max_score=0.0,
        elapsed_sec=99.0,
        scan_had_error=False,
        session_generation_id="a" * 64,
    )
    assert first.schema_version == SCAN_PUBLICATION_SNAPSHOT_SCHEMA_VERSION
    assert first.semantic_digest == second.semantic_digest
    with pytest.raises(TypeError):
        first.local_results["extra"] = {}  # type: ignore[index]


def test_phase29_report_set_activates_only_after_manifest_verification(tmp_path: Path) -> None:
    plan, snapshot = _snapshot(tmp_path)
    result = publish_scan_report_set(snapshot)

    assert not Path(plan.staging_path).exists()
    assert Path(plan.run_path).is_dir()
    assert Path(result.manifest_path).is_file()
    verified = verify_report_manifest(plan.run_path)
    assert verified.schema_version == REPORT_MANIFEST_SCHEMA_VERSION
    assert verified.snapshot_semantic_digest == snapshot.semantic_digest

    latest = json.loads(Path(plan.latest_path).read_text(encoding="utf-8"))
    assert latest["schema_version"] == LATEST_PUBLICATION_POINTER_SCHEMA_VERSION
    assert latest["completion_state"] == "complete"
    assert latest["scan_id"] == plan.scan_id
    assert latest["run_path"] == Path(plan.run_path).resolve().as_posix()
    assert latest["manifest_file_sha256"] == result.manifest_file_sha256


def test_phase29_unknown_staging_file_blocks_activation_and_preserves_latest(tmp_path: Path) -> None:
    plan, snapshot = _snapshot(tmp_path)
    latest = Path(plan.latest_path)
    latest.parent.mkdir(parents=True, exist_ok=True)
    previous = {"schema_version": "previous", "scan_id": "previous"}
    latest.write_text(json.dumps(previous), encoding="utf-8")
    (Path(plan.staging_path) / "unexpected.tmp").write_text("not governed", encoding="utf-8")

    with pytest.raises(RuntimeError, match="scan_report_staging_unknown_files"):
        publish_scan_report_set(snapshot)

    assert json.loads(latest.read_text(encoding="utf-8")) == previous
    assert Path(plan.staging_path).is_dir()
    assert not Path(plan.run_path).exists()


def test_phase29_manifest_tamper_is_rejected(tmp_path: Path) -> None:
    plan, snapshot = _snapshot(tmp_path)
    publish_scan_report_set(snapshot)
    results_path = Path(plan.run_path) / "scan_results.json"
    results_path.write_text("{}", encoding="utf-8")

    with pytest.raises(RuntimeError, match="report_manifest_file_mismatch"):
        verify_report_manifest(plan.run_path)


def test_phase29_session_generation_conflict_fails_closed(tmp_path: Path) -> None:
    plan = build_scan_log_output_plan(
        scan_id="scan-00000000000000000002-bbbbbbbbbbbbbbbbbbbb",
        root=tmp_path / "Scan Logs",
    )
    vt = VirusTotalReportingResult(
        status="disabled",
        config_digest="",
        config_path="",
        api_key_environment_variable="VIRUSTOTAL_API_KEY",
    )
    with pytest.raises(ValueError, match="scan_publication_session_generation_conflict"):
        build_scan_publication_snapshot(
            output_plan=plan,
            local_results={
                "a": {"scan_session_generation_id": "a" * 64},
                "b": {"scan_session_generation_id": "b" * 64},
            },
            ledger_summary={"record_count": 2},
            virustotal_result=vt,
            persistence_status={"ok": True},
            max_score=0.0,
            elapsed_sec=0.0,
            scan_had_error=False,
        )


def test_phase29_parent_log_is_closed_before_generation_rename(tmp_path: Path) -> None:
    generation = tmp_path / "Scan Logs/.staging/scan-log-release"
    log_path = generation / "scanlog"
    configure_single_parent_log(log_path)
    logging.warning("phase29 release proof")
    assert release_single_parent_log(log_path) is True
    final = tmp_path / "Scan Logs/runs/scan-log-release"
    final.parent.mkdir(parents=True)
    generation.replace(final)
    assert "phase29 release proof" in (final / "scanlog").read_text(encoding="utf-8")


def test_phase29_lifecycle_publishes_one_complete_generation(tmp_path: Path) -> None:
    plan = build_scan_log_output_plan(
        scan_id="scan-00000000000000000003-cccccccccccccccccccc",
        root=tmp_path / "Scan Logs",
    )
    Path(plan.staging_path).mkdir(parents=True)
    config_path = tmp_path / "VirusTotal/virustotal_config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(config_toml(VirusTotalConfig(enabled=False)), encoding="utf-8")
    log_path = plan.staging_report_path("scanlog")
    configure_single_parent_log(log_path)

    class Runtime:
        parent_cli = True
        scan_started_at = 0.0

        def __init__(self) -> None:
            self.values: dict[str, object] = {}

        def get(self, name: str, default: object = None) -> object:
            return self.values.get(name, default)

        def set(self, name: str, value: object) -> None:
            self.values[name] = value

    sample = tmp_path / "sample.py"
    sample.write_text("print('safe')\n", encoding="utf-8")
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

    runtime = Runtime()
    runtime.virustotal_runtime = initialize_virustotal_runtime(resource_root_snapshot_from_program_root(tmp_path))
    max_score, _elapsed = report_results(
        runtime,
        args,
        {sample.as_posix(): record},
        yara_ok=False,
        persistence_status={"ok": True},
    )

    assert max_score == 0.0
    assert not Path(plan.staging_path).exists()
    results_path = Path(plan.run_path) / "scan_results.json"
    assert results_path.is_file()
    assert not (Path(plan.run_path) / "scan_results.json.partial").exists()
    assert not (Path(plan.run_path) / "scan_results.json.partial.checkpoint.json").exists()
    published_results = json.loads(results_path.read_text(encoding="utf-8"))
    expected_results_digest = hashlib.sha256(
        json.dumps(
            published_results,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    assert runtime.values["SCAN_PUBLICATION_LOCAL_RESULTS_DIGEST"] == expected_results_digest
    assert (Path(plan.run_path) / "virustotal_results.json").is_file()
    assert (Path(plan.run_path) / "scanlog").is_file()
    assert (Path(plan.run_path) / "report_manifest.json").is_file()
    assert Path(plan.latest_path).is_file()
    assert runtime.values["SCAN_PUBLICATION_SNAPSHOT_DIGEST"]
    assert runtime.values["SCAN_PUBLICATION_RESULT"]["run_path"] == Path(plan.run_path).resolve().as_posix()
