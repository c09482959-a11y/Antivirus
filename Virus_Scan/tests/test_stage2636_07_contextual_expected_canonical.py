from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from Virus_Scan.detection.scoring.weighting import contextual_expected
from Virus_Scan.detection.scoring.weighting.contextual_expected import (
    ContextualExpectedScoreRequest,
    apply_contextual_expected_behavior_score_from_request,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def _persisted_state(bundle, count: int) -> dict[str, object]:
    records = {}
    for record in bundle.records:
        persisted = record.to_record()
        persisted["observation_count"] = count
        records[record.evidence_id] = persisted
    return {"records": records}


def test_contextual_expected_uses_one_semantic_record_per_root() -> None:
    bundle = physical_tag_evidence(
        ("file_read",),
        one_root=True,
        source_detector="contextual_expected",
        source_stage="score_input",
    )
    baseline = {
        "files": 30,
        "tag_evidence": _persisted_state(bundle, 30),
    }

    with patch.object(
        contextual_expected,
        "read_extension_baseline_snapshot",
        lambda _engine, _file_path: baseline,
    ):
        signal = contextual_expected.contextual_expected_behavior_signal(
            "other",
            "sample.txt",
            bundle,
        )

    assert set(bundle.tags) == {"file_read", "file_access"}
    assert signal["distinct_root_count"] == 1
    assert signal["expected_root_count"] == 1
    assert signal["expected_ratio"] == 1.0
    assert len(signal["records"]) == 1
    assert signal["records"][0]["root_observation_id"] == bundle.records[0].root_observation_id


def test_contextual_expected_score_requires_exact_tag_evidence() -> None:
    score, signal = apply_contextual_expected_behavior_score_from_request(
        ContextualExpectedScoreRequest(
            score=45.0,
            engine="other",
            file_path="sample.txt",
            tag_evidence=("file_read",),  # type: ignore[arg-type]
        )
    )

    assert score == 45.0
    assert signal["reason"] == "contextual_tag_evidence_required"
    assert signal["applied"] is False


def test_contextual_expected_positional_score_adapter_is_removed() -> None:
    source = Path(
        "Virus_Scan/detection/scoring/weighting/contextual_expected.py"
    ).read_text(encoding="utf-8")

    assert "def apply_contextual_expected_behavior_score(" not in source
    assert "Compatibility adapter" not in source
    assert not hasattr(
        contextual_expected,
        "apply_contextual_expected_behavior_score",
    )
