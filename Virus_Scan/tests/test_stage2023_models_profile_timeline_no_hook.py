from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path
from unittest.mock import patch

from Virus_Scan.models.profiles import timeline as profile_timeline



class HostileCount:
    touched = 0

    def _touch(self):
        type(self).touched += 1
        raise AssertionError("caller-owned numeric hook was invoked")

    def __float__(self):  # pragma: no cover - must not execute
        return self._touch()

    def __int__(self):  # pragma: no cover - must not execute
        return self._touch()

    def __bool__(self):  # pragma: no cover - must not execute
        return self._touch()


class HostileDict(dict):
    touched = 0

    def _touch(self):
        type(self).touched += 1
        raise AssertionError("caller-owned mapping hook was invoked")

    def __iter__(self):  # pragma: no cover - must not execute
        return self._touch()

    def get(self, *_args, **_kwargs):  # pragma: no cover - must not execute
        return self._touch()

    def items(self):  # pragma: no cover - must not execute
        return self._touch()


def test_stage2023_profile_timeline_unavailable_rejects_hostile_count_without_hooks() -> None:
    HostileCount.touched = 0

    record = profile_timeline.profile_timeline_unavailable("timeline_probe", sample_count=HostileCount())

    assert record["sample_count"] == 0
    assert record["final_json_must_record"] is True
    assert HostileCount.touched == 0


def test_stage2023_profile_timeline_rejects_hostile_baseline_counts_without_hooks() -> None:
    HostileDict.touched = 0
    baseline = {
        "timeline_baseline": {
            "sample_count": 10,
            "event_counts": HostileDict({"network": 10}),
            "transition_counts": {},
            "behavior_counts": {"network": 10},
            "behavior_transition_counts": {},
        }
    }

    with patch.object(profile_timeline, "get_extension_baseline", return_value=baseline):
        result = profile_timeline.extension_timeline_anomaly("renpy", "game.rpy", ("network",))

    assert result["ready"] is False
    assert result["reason"] == "non_finite_timeline_event_count"
    assert result["final_json_must_record"] is True
    assert HostileDict.touched == 0


def test_stage2023_profile_timeline_rejects_hostile_event_count_without_numeric_hooks() -> None:
    HostileCount.touched = 0
    baseline = {
        "timeline_baseline": {
            "sample_count": 10,
            "event_counts": {"network": HostileCount()},
            "transition_counts": {},
            "behavior_counts": {"network": 10},
            "behavior_transition_counts": {},
        }
    }

    with patch.object(profile_timeline, "get_extension_baseline", return_value=baseline):
        result = profile_timeline.extension_timeline_anomaly("renpy", "game.rpy", ("network",))

    assert result["ready"] is False
    assert result["reason"] == "non_finite_timeline_event_count"
    assert HostileCount.touched == 0


def test_stage2023_profile_timeline_source_has_no_backlog_numeric_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/timeline.py"))

    assert "safe_clamp" not in source
    assert "float(count)" not in source
    assert "float(value)" not in source
    assert "from collections.abc import Mapping" not in source
    assert ".get('timeline_baseline'" not in source
