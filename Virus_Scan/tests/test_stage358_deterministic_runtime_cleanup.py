from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from Virus_Scan.routing.baseline_routing import (
    BaselineRouteRequest,
    build_baseline_route,
)
from Virus_Scan.runtime.cleanup_invariants import RuntimeCleanupSnapshot
from Virus_Scan.runtime.determinism import (
    canonicalize_result_mapping,
    deterministic_json_digest,
    deterministic_json_dumps,
)


def test_stage358_baseline_lookup_preserves_contextual_order() -> None:
    route = build_baseline_route(BaselineRouteRequest(
        container_engine="renpy",
        artifact_engine="renpy",
        declared_extension=".rpy",
        sniffed_type="renpy_source",
        trusted_benign=True,
    ))
    assert route.baseline_lookup_order == (
        "renpy::renpy::.rpy::renpy_source",
        "renpy::renpy::.rpy",
        "renpy/.rpy",
        "renpy_source",
        "renpy/.rpy",
        ".rpy",
        "other",
    )
    assert route.blocked_baseline_keys == ("renpy/.rpy", ".rpy")


def test_stage358_deterministic_json_digest_is_order_stable() -> None:
    left = {
        "results": {
            "B/file.bin": {"tags": ["z", "a"], "evidence": [{"tag": "beta"}, {"tag": "alpha"}]},
            "a/file.bin": {"chains": ["stage2", "stage1"], "score": 80},
        }
    }
    right = {
        "results": {
            "a/file.bin": {"score": 80, "chains": ["stage1", "stage2"]},
            "B/file.bin": {"evidence": [{"tag": "alpha"}, {"tag": "beta"}], "tags": ["a", "z"]},
        }
    }
    assert deterministic_json_dumps(left) == deterministic_json_dumps(right)
    assert deterministic_json_digest(left) == deterministic_json_digest(right)


def test_stage358_canonical_result_mapping_removes_runtime_only_variance() -> None:
    left = {
        "sample.bin": {
            "verdict": "malicious",
            "tags": ["encoded", "chain"],
            "pid": 10,
            "duration": 1.25,
            "evidence": [{"tag": "payload", "source": "b"}, {"tag": "archive", "source": "a"}],
        }
    }
    right = {
        "sample.bin": {
            "duration": 9.0,
            "pid": 99,
            "evidence": [{"source": "a", "tag": "archive"}, {"source": "b", "tag": "payload"}],
            "tags": ["chain", "encoded"],
            "verdict": "malicious",
        }
    }
    assert canonicalize_result_mapping(left) == canonicalize_result_mapping(right)


def test_stage358_cleanup_snapshot_rejects_daemon_thread_masking() -> None:
    stop = threading.Event()
    thread = threading.Thread(target=stop.wait, name="stage358-daemon-worker", daemon=True)
    thread.start()
    try:
        snapshot = RuntimeCleanupSnapshot.capture()
        with pytest.raises(RuntimeError, match="stage358-daemon-worker"):
            snapshot.validate_clean(context="stage358_cleanup")
    finally:
        stop.set()
        thread.join(timeout=5)


def test_stage358_cleanup_snapshot_rejects_surviving_queue_and_tmp_artifacts(tmp_path: Path) -> None:
    (tmp_path / "work_queue" / "pending").mkdir(parents=True)
    (tmp_path / "work_queue" / "pending" / "job.json.tmp").write_text(json.dumps({"job": 1}), encoding="utf-8")
    snapshot = RuntimeCleanupSnapshot.capture(roots=(tmp_path,))
    with pytest.raises(RuntimeError, match="queue artifacts"):
        snapshot.validate_clean(context="stage358_queue_cleanup")
    with pytest.raises(RuntimeError, match="runtime tmp artifacts"):
        RuntimeCleanupSnapshot((), (), (), snapshot.tmp_artifacts).validate_clean(context="stage358_tmp_cleanup")
