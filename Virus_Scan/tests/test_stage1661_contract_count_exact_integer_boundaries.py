from __future__ import annotations

import json

from Virus_Scan.contracts.analytical_evidence import analytical_count_value, analytical_correlation_ceiling
from Virus_Scan.contracts.behavior_rarity import behavior_rarity_from_flow
from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int


def test_stage1661_no_hook_exact_nonnegative_int_rejects_nonintegral_floats_without_truncation() -> None:
    assert no_hook_exact_nonnegative_int(2.0, default=7) == (2, "")
    assert no_hook_exact_nonnegative_int(2.9, default=7) == (7, "unsafe_integer_value_rejected")
    assert no_hook_exact_nonnegative_int("2", default=7) == (2, "")
    assert no_hook_exact_nonnegative_int("2.9", default=7) == (7, "unsafe_integer_value_rejected")


def test_stage1661_analytical_counts_reject_nonintegral_floats_instead_of_truncating() -> None:
    assert analytical_count_value(2.0) == 2
    assert analytical_count_value(2.9) == 0

    ceiling = analytical_correlation_ceiling({"execution": 2.9, "network": 1})

    assert ceiling["active_families"] == {"network": 1}
    assert ceiling["capped_family_counts"] == {"network": 1}
    json.dumps(ceiling, sort_keys=True)


def test_stage1661_behavior_rarity_rejects_nonintegral_baseline_counts_instead_of_truncating() -> None:
    rejected_decimal = behavior_rarity_from_flow(("rare",), {"rare": 2.9, "other": 20}, min_support=1)
    explicit_rejection_baseline = behavior_rarity_from_flow(("rare",), {"other": 20}, min_support=1)
    truncated_baseline = behavior_rarity_from_flow(("rare",), {"rare": 2, "other": 20}, min_support=1)

    assert rejected_decimal == explicit_rejection_baseline
    assert rejected_decimal != truncated_baseline
    json.dumps({"rarity": rejected_decimal}, allow_nan=False, sort_keys=True)


def test_stage1661_behavior_rarity_rejects_nonintegral_min_support_instead_of_truncating() -> None:
    assert behavior_rarity_from_flow(("x",), {"y": 3}, min_support=3.0) > 0.0
    assert behavior_rarity_from_flow(("x",), {"y": 3}, min_support=3.7) == 0.0
