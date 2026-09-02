from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from Virus_Scan.contracts.path_identity import ScanPathPolicySnapshot, should_include_scan_path
from Virus_Scan.contracts.result_record import validate_replay_equivalent, validate_result_collection_invariants
from Virus_Scan.runtime.cleanup_invariants import RuntimeCleanupSnapshot, validate_runtime_cleanup


def test_stage357_output_artifacts_are_never_scan_inputs(tmp_path: Path) -> None:
    blocked = (
        tmp_path / "Scan Logs" / "scan_results.json",
        tmp_path / "Scan Logs" / "scan_results.json.partial",
        tmp_path / "Scan Logs" / "virustotal_results.json",
        tmp_path / "Scan Logs" / "scanlog",
        tmp_path / "Scan Logs" / "active.lock",
        tmp_path / "Temp" / "queue_state.tmp",
        tmp_path / "profiles" / "model_state.sqlite3",
        tmp_path / "work_queue" / "pending" / "job.json",
    )
    for path in blocked:
        assert should_include_scan_path(path) is False, path
    assert should_include_scan_path(tmp_path / "Game" / "Data" / "Managed" / "Assembly-CSharp.dll") is True


def test_stage357_scan_path_policy_snapshot_is_immutable_and_case_insensitive(tmp_path: Path) -> None:
    policy = ScanPathPolicySnapshot.canonical()
    with pytest.raises(AttributeError):
        policy.excluded_dirs = frozenset()  # type: ignore[misc]
    assert should_include_scan_path(tmp_path / "scan logs" / "SCANLOG") is False
    assert should_include_scan_path(tmp_path / "YARA" / "compiled_rules.yarc") is False


def test_stage357_result_collection_rejects_duplicate_json_records() -> None:
    payload = {
        "results": [
            {"file": "a.bin", "path": "a.bin", "verdict": "clean", "tags": ["benign_media"]},
            {"file": "a.bin", "path": "a.bin", "verdict": "clean", "tags": ["benign_media"]},
        ]
    }
    with pytest.raises(ValueError, match="duplicate result record"):
        validate_result_collection_invariants(payload, context="stage357_json")


def test_stage357_replay_equivalence_ignores_only_runtime_volatility() -> None:
    left = {
        "file": "sample.rpyc",
        "path": "sample.rpyc",
        "verdict": "malicious",
        "score": 91,
        "tags": ["pickle_exec_chain"],
        "chains": ["decode_then_execute"],
        "decoded_evidence_snippets": [{"payload": "pickle GLOBAL os system"}],
        "pid": 100,
        "duration_seconds": 1.5,
    }
    right = dict(left, pid=200, duration_seconds=9.0, worker_id="worker-9")
    assert validate_replay_equivalent(left, right, context="stage357_replay") is True
    divergent = dict(right, tags=["different_tag"])
    with pytest.raises(ValueError, match="deterministic replay mismatch"):
        validate_replay_equivalent(left, divergent, context="stage357_replay")


def test_stage357_runtime_cleanup_snapshot_rejects_surviving_non_daemon_thread() -> None:
    stop = threading.Event()
    thread = threading.Thread(target=stop.wait, name="stage357-owned-thread", daemon=False)
    thread.start()
    try:
        snapshot = RuntimeCleanupSnapshot.capture(ignored_thread_names=())
        with pytest.raises(RuntimeError, match="active threads"):
            snapshot.validate_clean(context="stage357_cleanup")
    finally:
        stop.set()
        thread.join(timeout=5)
    assert validate_runtime_cleanup(context="stage357_cleanup_after") is True


def test_stage357_json_reload_and_duplicate_validation_is_stable(tmp_path: Path) -> None:
    output = tmp_path / "scan_results.json"
    payload = {
        "results": [
            {"file": "clean.png", "path": "clean.png", "verdict": "clean", "tags": ["benign_media"]},
            {"file": "malicious.bin", "path": "malicious.bin", "verdict": "malicious", "score": 95, "tags": ["encoded_payload"], "decoded_evidence_snippets": [{"payload": "powershell -enc AAAA"}]},
        ]
    }
    output.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    loaded = json.loads(output.read_text(encoding="utf-8"))
    assert validate_result_collection_invariants(loaded, context="stage357_reload") is True
