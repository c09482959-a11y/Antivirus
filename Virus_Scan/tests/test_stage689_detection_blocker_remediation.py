"""Stage 689 detection blocker remediation validation.

These tests cover the explicit blockers from the Stage 688 audit: duplicate
cross-layer helpers, cluster/family fallback visibility, and real final JSON
writer failure behavior through the canonical reporting writer.
"""
from __future__ import annotations

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.tests.support.model_context_fixtures import model_context_snapshot_fixture
import ast
import hashlib
import json
from pathlib import Path

import pytest

from Virus_Scan.detection.correlation.multi_signal.cluster_result import (
    ClusterAssignment,
    cluster_assignment_from_context,
    failed_cluster_assignment,
)
from Virus_Scan.detection.evidence.failure_evidence import failure_evidence_payload, recoverable_failure_evidence
from Virus_Scan.detection.orchestration.full_analysis.pipeline import analyze_file_full_observe_only
from Virus_Scan.publication import json_writer as final_report

ROOT = Path("Virus_Scan")


def _cross_layer_duplicate_groups() -> list[list[tuple[str, str, int]]]:
    by_hash: dict[str, list[tuple[Path, str, int]]] = {}
    for path in ROOT.rglob("*.py"):
        if "__pycache__" in path.parts or "tests" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = ast.dump(ast.Module(body=node.body, type_ignores=[]), include_attributes=False)
                by_hash.setdefault(hashlib.sha256(body.encode()).hexdigest(), []).append((path, node.name, node.lineno))
    bad: list[list[tuple[str, str, int]]] = []
    for items in by_hash.values():
        if len(items) < 2:
            continue
        has_detection = any("detection" in path.parts for path, _, _ in items)
        has_external = any("detection" not in path.parts for path, _, _ in items)
        if has_detection and has_external:
            bad.append([(str(path), name, line) for path, name, line in items])
    return bad


def test_stage689_no_same_body_detection_cross_layer_helper_duplicates() -> None:
    assert _cross_layer_duplicate_groups() == []


def test_stage689_cluster_failure_keeps_unclustered_label_but_carries_failure_evidence() -> None:
    cluster = failed_cluster_assignment(
        stage_name="cluster_assignment",
        error=RuntimeError("injected cluster context failure"),
        error_source="stage689",
        affected_context="sample.exe",
    )
    assert isinstance(cluster, ClusterAssignment)
    assert str(cluster) == "unclustered"
    assert cluster.degraded is True
    assert cluster.scan_integrity["ok"] is False
    assert cluster.scan_integrity["json_record_required"] is True
    assert cluster.scan_integrity["replay_record_required"] is True
    assert any(item["stage_name"] == "cluster_assignment" for item in cluster.failure_evidence)
    json.dumps(cluster.to_record(), sort_keys=True)


def test_stage689_successful_unclustered_label_is_not_marked_degraded() -> None:
    cluster = cluster_assignment_from_context(model_context_snapshot_fixture(cluster_id=None))
    assert str(cluster) == "unclustered"
    assert cluster.degraded is False
    assert cluster.failure_evidence == ()
    assert cluster.scan_integrity["ok"] is True


def test_stage689_real_final_json_writer_failure_is_not_clean_success(tmp_path: Path) -> None:
    sample = tmp_path / "payload.rpy"
    sample.write_text("init python:\n os.system('powershell -enc AAA')", encoding="utf-8")
    result = analyze_file_full_observe_only(sample, tags=["renpy_script", "powershell_exec"], scan_session_snapshot=scan_session_snapshot_fixture(), artifact_read_snapshot=artifact_read_snapshot_fixture(sample))
    assert result.get("tags")

    blocked_parent = tmp_path / "blocked-parent"
    blocked_parent.write_text("not a directory", encoding="utf-8")
    output = blocked_parent / "scan_results.json"
    with pytest.raises(RuntimeError, match="final scan_results.json write failed"):
        final_report.finalize_scan_results(
            str(output),
            {str(sample): result},
        )

    failure = recoverable_failure_evidence(
        stage_name="final_json_writer",
        error=OSError("injected real final JSON replace failure"),
        error_source="finalize_scan_results",
        affected_context=str(output),
    )
    payload = failure_evidence_payload((failure,))
    assert payload["degraded"] is True
    assert payload["json_record_required"] is True
    assert payload["replay_record_required"] is True
    assert result.get("tags"), "writer failure must not erase produced detection evidence"
    assert not output.exists(), "failed final writer must not leave a misleading clean final JSON"
