from __future__ import annotations

import json
import math

from Virus_Scan.contracts.behavior_rarity import behavior_rarity_from_flow
from Virus_Scan.detection.scoring.weighting.behavior_learning import tag_rarity_score


def test_stage1323_behavior_rarity_ignores_nonfinite_baseline_counts_without_crashing():
    corrupt_baseline = {
        "decode": float("nan"),
        "exec": float("inf"),
        "network": float("-inf"),
        "bad": "not-a-count",
    }

    rarity = behavior_rarity_from_flow(("decode", "exec"), corrupt_baseline, min_support=1)

    assert rarity == 0.0
    json.dumps({"rarity": rarity}, allow_nan=False)


def test_stage1323_behavior_rarity_preserves_valid_counts_when_corrupt_counts_are_present():
    clean_baseline = {"decode": 20, "exec": 1, "network": 3}
    corrupt_baseline = {
        **clean_baseline,
        "nan_support": float("nan"),
        "infinite_support": float("inf"),
        "negative_infinite_support": float("-inf"),
        "string_support": "bad-count",
    }

    expected = behavior_rarity_from_flow(("decode", "exec"), clean_baseline)
    actual = behavior_rarity_from_flow(("decode", "exec"), corrupt_baseline)

    assert actual == expected
    json.dumps({"rarity": actual}, allow_nan=False)


def test_stage1323_detection_rarity_caller_projects_corrupt_baseline_to_cold_start():
    rarity = tag_rarity_score(["decode", "exec"], {"decode": math.inf, "exec": math.nan})

    assert rarity == 0.0
    json.dumps({"rarity": rarity}, allow_nan=False)
