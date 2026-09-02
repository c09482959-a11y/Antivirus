"""Stage 1490: parent replay learning detaches result iterables before replay."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Iterator

from Virus_Scan.models.replay.api import persist_parent_learning_from_results
from Virus_Scan.models.replay.learning import _add_summary_count


class UnreadableValuesMapping(Mapping[str, Any]):
    def __getitem__(self, key: str) -> Any:
        return {"file": "sample.py", "classification": "benign"}

    def __iter__(self) -> Iterator[str]:
        return iter(("one",))

    def __len__(self) -> int:
        return 1

    def values(self):  # pragma: no cover - failure path if not caught by owner
        raise RuntimeError("caller-owned replay results values failed")


class HostileSummaryValue:
    def __bool__(self) -> bool:  # pragma: no cover - failure if truthiness fallback is used
        raise RuntimeError("summary value must not be truth-tested")

    def __int__(self) -> int:
        return 2


def test_stage1490_parent_replay_learning_mapping_values_failure_is_degraded_evidence() -> None:
    summary = persist_parent_learning_from_results(UnreadableValuesMapping())

    assert summary["errors"] == 1
    assert summary["degraded"] is True
    assert summary["unavailable_reason"] == "parent_replay_results_mapping_values_failed"


def test_stage1490_replay_summary_count_avoids_truthiness_fallback() -> None:
    totals = {"checked": 0}

    _add_summary_count(totals, {"checked": HostileSummaryValue()}, "checked")

    assert totals["checked"] == 0
