from __future__ import annotations

from pathlib import Path

from Virus_Scan.detection.correlation.multi_signal.cluster_result import (
    ClusterAssignment,
    failed_cluster_assignment,
)
from Virus_Scan.detection.models.failure_state import failure_state_records
from Virus_Scan.detection.scoring.weighting.chain_bonus import cap_noise_only_score


def test_stage2068_cluster_assignment_carries_typed_degraded_evidence() -> None:
    assignment = failed_cluster_assignment(
        stage_name="stage2068",
        error=ValueError("bad cluster"),
        error_source="test",
        affected_context="cluster",
    )

    assert isinstance(assignment, ClusterAssignment)
    assert assignment.degraded is True
    assert assignment.scan_integrity["failure_count"] == 1
    assert assignment.failure_payload["failure_count"] == 1
    assert assignment.to_record()["degraded"] is True


def test_stage2068_failure_state_uses_descriptor_safe_exception_args_and_finite_float_policy() -> None:
    source = Path("Virus_Scan/detection/models/failure_state.py").read_text(encoding="utf-8")

    assert "BaseException.args.__get__" not in source
    assert "math.isfinite(value)" in source
    records = failure_state_records(({"score": float("nan")},))
    assert records[0]["score"]["unavailable_reason"] == "detection_failure_nonfinite_float"


def test_stage2068_chain_bonus_wrapper_uses_canonical_noise_gate_owner() -> None:
    source = Path("Virus_Scan/detection/scoring/weighting/chain_bonus.py").read_text(encoding="utf-8")

    assert "cap_noise_only_score as apply_noise_only_score_cap" in source
    assert "return cap_noise_only_score(score, norm" not in source
    capped = cap_noise_only_score(90.0, ["support_only"], stage="stage2068")
    assert isinstance(capped, float)


def test_stage2068_full_suite_live_scan_uses_single_runtime_entrypoint() -> None:
    source = Path("Virus_Scan/tests/test_stage359_deterministic_integration_runtime.py").read_text(encoding="utf-8")
    runtime_entrypoint = "Virus_Scan" + ".runtime_main"
    startup_entrypoint = "Virus_Scan" + ".main"

    assert f'"{runtime_entrypoint}"' in source
    assert f'"{startup_entrypoint}"' not in source
