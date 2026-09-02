from __future__ import annotations

import json

from Virus_Scan.models import clustering


def test_stage1331_online_vector_update_resets_corrupt_baseline_count_and_vectors() -> None:
    baseline = {
        "count": float("inf"),
        "mean": [float("nan"), 99.0],
        "m2": [1.0, float("inf")],
        "variance": [float("inf"), 3.0],
        "feature_names": ["a", "b"],
        "updated": float("inf"),
    }

    updated = clustering.online_vector_update(baseline, [2.5, float("-inf")], ["a", "b"])

    assert updated["count"] == 1
    assert updated["mean"] == (2.5, 0.0)
    assert updated["m2"] == (0.0, 0.0)
    assert updated["variance"] == (0.0, 0.0)
    assert updated["updated"] == 1.0
    assert updated["updated_source"] == "deterministic_update_count"
    json.dumps(updated, allow_nan=False, sort_keys=True)


def test_stage1331_online_vector_update_preserves_valid_finite_baseline_update() -> None:
    baseline = {
        "count": 2,
        "mean": [2.0, 4.0],
        "m2": [2.0, 8.0],
        "variance": [2.0, 8.0],
        "feature_names": ["a", "b"],
        "updated": 2.0,
    }

    updated = clustering.online_vector_update(baseline, [5.0, 1.0], ["a", "b"])

    assert updated["count"] == 3
    assert updated["mean"] == (3.0, 3.0)
    assert updated["m2"] == (8.0, 14.0)
    assert updated["variance"] == (4.0, 7.0)
    json.dumps(updated, allow_nan=False, sort_keys=True)
