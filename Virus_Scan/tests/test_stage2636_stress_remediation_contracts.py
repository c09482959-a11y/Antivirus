from __future__ import annotations

import hashlib
import json
import pytest
from pathlib import Path

from Virus_Scan.publication.scan_result_ledger import canonical_record_digest, emit_scan_result_ledger, parse_scanlog_ledger
from Virus_Scan.stress.corpus_materializer import materialize_malicious_corpus
from Virus_Scan.stress.malicious_corpus import build_malicious_oracle_manifest
from Virus_Scan.stress.profile_verifier import verify_no_malicious_profile_learning
from Virus_Scan.stress.run_verifier import verify_stress_run
from Virus_Scan.scheduler.orchestration.scheduler_pipeline_runtime import (
    SchedulerPipelineRunState,
    build_partial_result_writer,
)



class _CheckpointDependencies:
    def __init__(self) -> None:
        self.materialized = 0
        self.requests: list[object] = []
        self.deltas: list[object] = []
        self.time = lambda: 1.0
        self.environ_get = lambda _name, default: default
        self.write_partial_scan_results = lambda *_args, **_kwargs: True
        self.log_error = lambda _message: None

    def make_json_safe(self, value: object) -> object:
        self.materialized += 1
        return dict(value) if type(value) is dict else value

    def write_partial_scheduler_results(self, **values: object) -> float:
        self.requests.append(dict(values))
        cache = values["checkpoint_cache"]
        results = values["results"]
        if values["force"]:
            cache.reconcile_results(results, values["make_json_safe"])
        else:
            cache.observe_latest_terminal(results, values["make_json_safe"])
        delta = cache.pending_delta()
        self.deltas.append(delta)
        self.write_partial_scan_results("scan_results.json.partial", delta)
        cache.commit_delta(delta)
        return float(len(self.requests))

def _load_manifest(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _valid_record(root: Path, case: dict[str, object]) -> dict[str, object]:
    absolute = str((root / "corpus" / str(case["relative_path"])).resolve())
    return {
        "sample_id": case["sample_id"],
        "input_file_path": absolute,
        "normalized_path": absolute,
        "sha256": case["sha256"],
        "final_sha256": case["sha256"],
        "classification": "malicious",
        "verdict": "malicious",
        "score": case["minimum_score"],
        "tags": case["required_tags"],
        "exit_code": 3,
        "final_status": case["expected_terminal_status"],
        "learn_eligible": False,
        "learning_reason": case["expected_profile_learning"],
        "scheduler_mode": "serial",
    }


def _write_valid_artifacts(root: Path, count: int = 2) -> tuple[dict[str, object], dict[str, object]]:
    for relative in ("Scan Logs/.staging/stage2636", "profiles", "manifests"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    materialized = materialize_malicious_corpus(
        root / "corpus",
        count,
        manifest_path=root / "manifests" / "malicious_manifest.json",
        run_id="stage2636-test",
    )
    manifest = _load_manifest(Path(materialized.manifest_path))
    final: dict[str, object] = {}
    checkpoint: dict[str, object] = {}
    for case in manifest["cases"]:
        assert type(case) is dict
        record = _valid_record(root, case)
        path = str(record["input_file_path"])
        final[path] = record
        checkpoint[path] = {
            "file": path,
            "node": path,
            "classification": record["classification"],
            "score": record["score"],
            "tags": record["tags"],
        }
    final_path = root / "Scan Logs" / ".staging" / "stage2636" / "scan_results.json"
    checkpoint_path = root / "Scan Logs" / ".staging" / "stage2636" / "scan_results.json.partial.checkpoint.json"
    final_path.write_text(json.dumps(final), encoding="utf-8")
    checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
    lines: list[str] = []
    emit_scan_result_ledger(final, final_path, log_info=lines.append, persistence_status={"ok": True})
    (root / "Scan Logs" / ".staging" / "stage2636" / "scanlog").write_text("\n".join(lines), encoding="utf-8")
    return final, manifest


def test_stage2636_oracle_has_exact_unique_10000_malicious_cases() -> None:
    manifest = build_malicious_oracle_manifest()
    ids = tuple(case.sample_id for case in manifest.cases)
    paths = tuple(case.relative_path for case in manifest.cases)

    assert manifest.total_samples == 10_000
    assert len(manifest.cases) == 10_000
    assert len(frozenset(ids)) == 10_000
    assert len(frozenset(paths)) == 10_000
    assert all(case.expected_classifications == ("malicious",) for case in manifest.cases)
    assert all(case.extension != ".txt" for case in manifest.cases)
    assert {case.extension for case in manifest.cases} == {".ps1", ".js", ".py", ".bat", ".cmd", ".vbs", ".hta"}


def test_stage2636_materializer_keeps_manifest_outside_corpus_and_verifies_hashes(tmp_path: Path) -> None:
    materialized = materialize_malicious_corpus(tmp_path / "corpus", 7, run_id="stage2636-materializer")
    manifest_path = Path(materialized.manifest_path)

    assert manifest_path.parent == tmp_path / "manifests"
    assert not manifest_path.is_relative_to(tmp_path / "corpus")
    assert len(materialized.samples) == 7
    for sample in materialized.samples:
        source = Path(sample.absolute_path)
        assert source.is_file() and not source.is_symlink()
        assert source.stat().st_size == sample.size_bytes
        assert hashlib.sha256(source.read_bytes()).hexdigest() == sample.sha256


def test_stage2636_ledger_digest_is_bound_to_full_final_record(tmp_path: Path) -> None:
    final_path = tmp_path / "scan_results.json"
    final_path.write_text("{}", encoding="utf-8")
    record = {
        "sample_id": "malicious_00000",
        "sha256": "a" * 64,
        "classification": "malicious",
        "score": 92.0,
        "tags": ["encoded_powershell", "network_download"],
        "errors": ["bounded"],
    }
    lines: list[str] = []
    summary = emit_scan_result_ledger({"sample": record}, final_path, log_info=lines.append, persistence_status={"ok": True})
    parsed = parse_scanlog_ledger(lines)
    ledger = parsed["results"][0]

    assert ledger["record_digest"] == canonical_record_digest(record)
    assert ledger["score"] == 92.0
    assert ledger["tags"] == ["encoded_powershell", "network_download"] or ledger["tags"] == ("encoded_powershell", "network_download")
    assert summary["duplicate_sample_ids"] == 0
    assert summary["missing_sha256"] == 0


def test_stage2636_independent_verifier_accepts_complete_artifacts(tmp_path: Path) -> None:
    _write_valid_artifacts(tmp_path, 2)
    report = verify_stress_run(tmp_path, expected_count=2, scanner_exit_code=3)

    assert report.passed is True
    assert report.oracle_pass_count == 2
    assert report.missing_count == 0
    assert report.duplicate_count == 0
    assert report.profile_violation_count == 0


def test_stage2636_independent_verifier_rejects_wrong_oracle_and_duplicate_identity(tmp_path: Path) -> None:
    final, _manifest = _write_valid_artifacts(tmp_path, 2)
    first = next(iter(final.values()))
    assert type(first) is dict
    first["classification"] = "benign_clean"
    final["duplicate-key"] = dict(first)
    final_path = tmp_path / "Scan Logs" / ".staging" / "stage2636" / "scan_results.json"
    final_path.write_text(json.dumps(final), encoding="utf-8")
    lines: list[str] = []
    emit_scan_result_ledger(final, final_path, log_info=lines.append, persistence_status={"ok": True})
    (tmp_path / "Scan Logs" / ".staging" / "stage2636" / "scanlog").write_text("\n".join(lines), encoding="utf-8")

    report = verify_stress_run(tmp_path, expected_count=2, scanner_exit_code=3)

    assert report.passed is False
    assert report.duplicate_count > 0
    assert report.mismatch_count > 0


def test_stage2636_profile_verifier_rejects_clean_learning_and_malicious_identity(tmp_path: Path) -> None:
    materialized = materialize_malicious_corpus(tmp_path / "corpus", 1)
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    sample = materialized.samples[0]
    profile = {
        "engine": "other",
        "extension_baselines": {
            ".ps1": {"files": 1, "learning_gate": {"accepted": 1}, "sample_sha256": sample.sha256}
        },
        "model_state": {},
    }
    (profiles / "other.json").write_text(json.dumps(profile), encoding="utf-8")

    report = verify_no_malicious_profile_learning(profiles, materialized.manifest_path)

    assert report.ok is False
    assert any(issue.reason in {"profile_invariant_violation", "malicious_sha256_learned"} for issue in report.issues)



def test_stage2636_checkpoint_cache_materializes_each_terminal_record_once() -> None:
    state = SchedulerPipelineRunState(results={})
    dependencies = _CheckpointDependencies()
    writer = build_partial_result_writer(
        state=state, dependencies=dependencies, partial_output_path="scan_results.json",
        total_files=3, partial_output_every=1,
    )

    state.results["a"] = {"score": 1}
    writer(force=False)
    state.results["b"] = {"score": 2}
    writer(force=False)

    assert dependencies.materialized == 2
    first, second = dependencies.deltas
    assert len(first.items) == 1
    assert len(second.items) == 1
    assert first.total_records == 1
    assert second.total_records == 2

    state.results["a"] = {"score": 3}
    with pytest.raises(RuntimeError, match="checkpoint_terminal_record_replaced"):
        writer(force=True)
    assert dependencies.materialized == 2

def test_stage2636_repairs_do_not_use_monkey_patching_or_compatibility_layers() -> None:
    root = Path(__file__).resolve().parents[1]
    targets = (
        root / "stress" / "malicious_corpus.py",
        root / "stress" / "corpus_materializer.py",
        root / "stress" / "run_verifier.py",
        root / "stress" / "profile_verifier.py",
        root / "stress" / "stress_runner.py",
        root / "publication" / "scan_result_ledger.py",
    )
    forbidden = ("monkeypatch", "unittest.mock", "compatibility wrapper", "compat shim", "sys.modules[")

    for target in targets:
        source = target.read_text(encoding="utf-8").lower()
        assert all(item not in source for item in forbidden), target
