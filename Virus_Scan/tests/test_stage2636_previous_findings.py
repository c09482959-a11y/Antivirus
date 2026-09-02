from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from Virus_Scan.models.profiles import persistence as profile_persistence
from Virus_Scan.models.profiles.snapshots import default_engine_profile
from Virus_Scan.publication.json_writer import finalize_scan_results
from Virus_Scan.publication.json_finalization import streaming
from Virus_Scan.publication.scan_result_ledger import emit_scan_result_ledger, parse_scanlog_ledger
from Virus_Scan.routing.context_container_fingerprints import container_fingerprint
from Virus_Scan.routing.context_evidence_context import RoutingEvidenceContext
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state
from Virus_Scan.scheduler.orchestration.finalization import (
    SchedulerPipelineFinalizationDependencies,
    SchedulerPipelineFinalizationRequest,
    finalize_scheduler_pipeline,
)
from Virus_Scan.scheduler.orchestration.scheduler_serial_mode import (
    SchedulerSerialModeDependencies,
    SchedulerSerialModeRequest,
    run_scheduler_serial_mode,
)
from Virus_Scan.stress.corpus_materializer import materialize_malicious_corpus
from Virus_Scan.stress.profile_verifier import verify_no_malicious_profile_learning
from Virus_Scan.stress.run_verifier import verify_malicious_scan_artifacts
from Virus_Scan.models.profiles.context import contextual_profile_learning_policy


def _isolate_profiles(tmp_path: Path) -> Path:
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    configure_profiles_dir(str(profiles_dir))
    profile_persistence_state().bind_profiles_dir(str(profiles_dir))
    return profiles_dir


def test_stage2636_profile_flush_accepts_force_keyword(tmp_path: Path) -> None:
    profiles_dir = _isolate_profiles(tmp_path)
    profile = default_engine_profile("other")

    profile_persistence.save_engine_profile("other", profile, force=True)

    assert profile_persistence.flush_profile_writes(force=True) is True
    assert (profiles_dir / "model_state.sqlite3").exists()
    assert not tuple(profiles_dir.glob("*.json*"))


def test_stage2636_publication_flush_reports_each_persistent_store(tmp_path: Path) -> None:
    script = """
import json
from Virus_Scan.init_runtime.top_level import run_top_level_init
from Virus_Scan.orchestration.bootstrap_initialization import initialize_runtime
from Virus_Scan.publication.api import flush_all_persistent_models
initialize_runtime()
run_top_level_init()
print(json.dumps(flush_all_persistent_models(force=True), sort_keys=True))
"""
    environment = dict(os.environ)
    environment["UMIGE_BASE_DIR"] = str(tmp_path)
    completed = subprocess.run(
        (sys.executable, "-c", script),
        cwd=Path(__file__).resolve().parents[2],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    result = json.loads(completed.stdout.strip().splitlines()[-1])

    assert result["ok"] is True
    assert set(result["stores"]) == {"learning_candidates", "model_state", "scan_cache"}
    assert all(store["ok"] is True for store in result["stores"].values())


def test_stage2636_scheduler_finalization_fails_structured_flush_status() -> None:
    calls: list[object] = []

    finalize_scheduler_pipeline(
        SchedulerPipelineFinalizationRequest(
            results={"sample": {"fast_path": False, "learn_eligible": True}},
            scheduler_mode="process",
            strict=False,
            process_shard=False,
            freeze_existing_baselines=False,
            profile_policy_snapshot="snapshot",
        ),
        SchedulerPipelineFinalizationDependencies(
            persist_parent_learning_from_results=lambda results: calls.append(("persist", tuple(results))),
            flush_all_persistent_models=lambda force=True: {
                "ok": False,
                "stores": {"engine_profiles": {"ok": False}},
            },
            restore_profile_policy=lambda snapshot: calls.append(("restore", snapshot)),
            clear_profile_scoring_snapshot=lambda: calls.append("clear"),
            write_partial=lambda **kwargs: calls.append(("partial", kwargs.get("force"))),
            log_error=lambda message: calls.append(("error", message)),
            recoverable_exceptions=(Exception,),
        ),
    )

    assert ("error", "persistent model flush failed at pipeline end: persistent_model_flush_failed") in calls
    assert ("restore", "snapshot") in calls
    assert ("partial", True) in calls


def test_stage2636_final_json_publishes_key_identity_and_sha256(tmp_path: Path) -> None:
    sample = tmp_path / "malicious_00001__fixture.ps1"
    sample.write_text("powershell encodedcommand runonce", encoding="utf-8")
    output = tmp_path / "scan_results.json"

    assert finalize_scan_results(
        str(output),
        {str(sample): {"classification": "malicious", "score": 100.0, "tags": ["powershell"]}},
    )

    data = json.loads(output.read_text(encoding="utf-8"))
    record = data[str(sample)]
    assert record["input_file_path"].replace("\\", "/").endswith("malicious_00001__fixture.ps1")
    assert record["sample_id"] == "malicious_00001"
    assert record["sha256"] == hashlib.sha256(sample.read_bytes()).hexdigest()
    assert record["final_sha256"] == record["sha256"]


def test_stage2636_finalization_preserves_checkpoint_evidence_and_removes_live_partial(tmp_path: Path) -> None:
    output = tmp_path / "scan_results.json"
    partial = Path(str(output) + ".partial")
    checkpoint = Path(str(output) + ".partial.checkpoint.json")
    partial.write_text(json.dumps({"old": {"score": 5}}), encoding="utf-8")

    assert finalize_scan_results(str(output), {"sample": {"classification": "benign", "score": 0}})

    assert not partial.exists()
    assert checkpoint.exists()
    assert json.loads(checkpoint.read_text(encoding="utf-8")) == {"old": {"score": 5}}


def test_stage2636_partial_writer_preserves_raw_checkpoint_records(tmp_path: Path) -> None:
    output = tmp_path / "scan_results.json.partial"
    raw = {"sample": {"score": 1, "stage2636_raw_checkpoint_marker": "present"}}

    assert streaming.write_partial_scan_results(str(output), raw)

    written = json.loads(output.read_text(encoding="utf-8"))
    record = written["sample"]
    assert record["stage2636_raw_checkpoint_marker"] == "present"
    assert record["score"] == 1
    assert "schema_version" not in record


def test_stage2636_scanlog_ledger_reconciles_final_records(tmp_path: Path) -> None:
    final_json = tmp_path / "scan_results.json"
    final_json.write_text("{}", encoding="utf-8")
    lines: list[str] = []

    summary = emit_scan_result_ledger(
        {"sample": {"sample_id": "sample", "sha256": "a" * 64, "classification": "malicious", "exit_code": 2}},
        str(final_json),
        log_info=lines.append,
        persistence_status={"ok": True},
    )
    parsed = parse_scanlog_ledger(lines)

    assert summary["record_count"] == 1
    assert len(parsed["results"]) == 1
    assert parsed["summaries"][0]["persistence_ok"] is True


def test_stage2636_scan_owned_routing_context_is_immutable_and_reused(tmp_path: Path) -> None:
    root = tmp_path / "game_root"
    game = root / "game"
    game.mkdir(parents=True)
    first = game / "first.rpy"
    first.write_text("label start:", encoding="utf-8")

    context = RoutingEvidenceContext.build(root)
    initial = contextual_profile_learning_policy(first, trusted_benign=True, evidence_context=context)

    first.unlink()
    (root / "UnityPlayer.dll").write_bytes(b"MZ")
    second = game / "second.rpy"
    second.write_text("label second:", encoding="utf-8")
    reused = contextual_profile_learning_policy(second, trusted_benign=True, evidence_context=context)
    live = contextual_profile_learning_policy(second, trusted_benign=True)

    assert initial.container_engine == "renpy"
    assert reused.container_engine == initial.container_engine
    assert reused.baseline_key == initial.baseline_key
    assert reused.fingerprint_evidence == initial.fingerprint_evidence
    assert live.fingerprint_evidence != reused.fingerprint_evidence


def test_stage2636_container_fingerprint_has_no_stale_process_global_cache(tmp_path: Path) -> None:
    root = tmp_path / "container"
    game = root / "game"
    game.mkdir(parents=True)
    script = game / "script.rpy"
    script.write_text("label start:", encoding="utf-8")

    before = container_fingerprint(root, script)
    script.unlink()
    (root / "UnityPlayer.dll").write_bytes(b"MZ")
    probe = root / "probe.bin"
    probe.write_bytes(b"data")
    after = container_fingerprint(root, probe)

    assert before.engine == "renpy"
    assert after.engine != before.engine


def test_stage2636_serial_partial_publication_uses_live_results() -> None:
    live_results: dict[object, object] = {}
    seen: list[tuple[object, ...]] = []

    def worker(path: str, _previous_stage: str, _strict: bool) -> tuple[str, dict[str, object]]:
        return path, {"effective_stage": "script", "tags": ["script"]}

    def write_partial(_force: bool) -> None:
        seen.append(tuple(sorted(live_results)))

    run_scheduler_serial_mode(
        SchedulerSerialModeRequest(
            files=("a.py", "b.py"),
            total_files=2,
            started_at=0.0,
            progress_every=1,
            throttle_sec=0.0,
            results=live_results,
        ),
        SchedulerSerialModeDependencies(
            worker=worker,
            prepare_result=lambda _path, result: result,
            write_derived_cache=lambda _result: False,
            write_partial=write_partial,
            bulk_scan_maintenance=lambda _count: None,
            log_bulk_progress=lambda *_args, **_kwargs: None,
            sleep=lambda _seconds: None,
        ),
    )

    assert seen[0] == ("a.py",)
    assert seen[1] == ("a.py", "b.py")


def test_stage2636_malicious_corpus_and_verifiers_reconcile_artifacts(tmp_path: Path) -> None:
    materialized = materialize_malicious_corpus(tmp_path / "corpus", count=3)
    manifest = json.loads(Path(materialized.manifest_path).read_text(encoding="utf-8"))
    final_json = tmp_path / "scan_results.json"
    scanlog = tmp_path / "scanlog"
    final_results = {}
    for case in manifest["cases"]:
        final_results[case["relative_path"]] = {
            "sample_id": case["sample_id"],
            "sha256": case["sha256"],
            "classification": "malicious",
            "verdict": "malicious",
            "score": case["minimum_score"],
            "tags": case["required_tags"],
            "exit_code": 3,
            "final_status": case["expected_terminal_status"],
            "learn_eligible": False,
        }
    final_json.write_text(json.dumps(final_results), encoding="utf-8")
    lines: list[str] = []
    emit_scan_result_ledger(final_results, str(final_json), log_info=lines.append, persistence_status={"ok": True})
    scanlog.write_text("\n".join(lines), encoding="utf-8")

    artifact_report = verify_malicious_scan_artifacts(
        final_json_path=final_json,
        scanlog_path=scanlog,
        oracle_manifest_path=materialized.manifest_path,
    )
    profile_report = verify_no_malicious_profile_learning(tmp_path / "profiles", materialized.manifest_path)

    assert artifact_report.ok is True
    assert profile_report.ok is True

    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir(exist_ok=True)
    (profiles_dir / "other.json").write_text(manifest["cases"][0]["sha256"], encoding="utf-8")
    violated = verify_no_malicious_profile_learning(profiles_dir, materialized.manifest_path)
    assert violated.ok is False


def test_stage2636_has_one_canonical_all_store_flush_owner() -> None:
    root = Path(__file__).resolve().parents[1]
    jsonio_source = (root / "core" / "jsonio.py").read_text(encoding="utf-8")
    publication_source = (root / "publication" / "api" / "pipeline_finalization.py").read_text(encoding="utf-8")
    cache_source = (root / "core" / "cache.py").read_text(encoding="utf-8")

    assert "def flush_all_persistent_models" not in jsonio_source
    assert publication_source.count("def flush_all_persistent_models") == 1
    assert "scan_cache_repository().maintenance(force=True)" in cache_source
