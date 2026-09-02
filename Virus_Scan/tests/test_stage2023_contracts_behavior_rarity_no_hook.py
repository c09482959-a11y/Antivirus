from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.contracts.behavior_rarity import behavior_rarity_from_flow



class HostileBaseline(dict):
    touched = 0

    def values(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned values hook was invoked")

    def items(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned items hook was invoked")

    def get(self, *_args, **_kwargs):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned get hook was invoked")


class PlainSequence:
    def __init__(self, values):
        self.values = values


def test_stage2023_behavior_rarity_uses_owned_baseline_items() -> None:
    rarity = behavior_rarity_from_flow(("rare", "common"), {"rare": 1, "common": 40}, min_support=1)

    assert 0.0 <= rarity <= 1.0


def test_stage2023_behavior_rarity_rejects_hostile_baseline_hooks() -> None:
    HostileBaseline.touched = 0

    rarity = behavior_rarity_from_flow(("rare",), HostileBaseline({"rare": 1}), min_support=1)

    assert rarity == 0.0
    assert HostileBaseline.touched == 0


def test_stage2023_behavior_rarity_plain_sequence_uses_instance_dict_no_hook() -> None:
    rarity = behavior_rarity_from_flow(PlainSequence(["rare"]), {"common": 20}, min_support=1)

    assert rarity > 0.0


def test_stage2023_behavior_rarity_source_removed_backlog_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/contracts/behavior_rarity.py"))

    forbidden = (
        "total = sum(baseline_snapshot.values())",
        "values.append(1.0 - safe_clamp(probability))",
        "return safe_clamp(sum(values) / max(1, len(values)))",
        "values = data.get(\"values\")",
        "_MAPPING_PROXY_TYPE",
    )
    for snippet in forbidden:
        assert snippet not in source
