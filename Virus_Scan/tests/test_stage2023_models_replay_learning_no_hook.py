from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path
from unittest.mock import patch

from Virus_Scan.models.replay import learning as replay_learning
from Virus_Scan.models.replay.transaction_projection import project_runtime_transaction_stats
from Virus_Scan.models.replay.learning_boundaries import safe_summary_count



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

    def values(self):  # pragma: no cover - must not execute
        return self._touch()


class HostileCount:
    touched = 0

    def __int__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned integer hook was invoked")


def _payload() -> dict[str, object]:
    return {
        "file_path": "game/script.rpy",
        "integrity": {"allow_learning": True},
        "verdict": "clean",
        "engine": "renpy",
        "tags": ["benign_asset"],
        "yara_hits": [],
        "score": 0.0,
        "api_calls": [],
        "ordered_events": [],
    }


def test_stage2023_parent_replay_payload_unavailable_uses_no_hook_mapping_read() -> None:
    result = {}

    with patch.object(
        replay_learning,
        "result_learning_payload",
        return_value={"replay_payload_unavailable": True, "reason": "payload_failed"},
    ):
        summary = replay_learning.parent_replay_result_learning(result)

    assert summary["errors"] == 1
    assert summary["degraded"] is True
    assert summary["skipped"] == "payload_failed"


def test_stage2023_parent_replay_learning_result_rejects_hostile_mapping_hooks() -> None:
    HostileDict.touched = 0

    with (
        patch.object(replay_learning, "result_learning_payload", return_value=_payload()),
        patch.object(replay_learning, "is_passive_fast_asset_result", return_value=False),
        patch.object(replay_learning, "commit_promoted_learning", return_value=HostileDict({"learned": True, "promoted": True})),
    ):
        summary = replay_learning.parent_replay_result_learning({})

    assert summary["clean_checked"] == 1
    assert summary["committed"] == 0
    assert summary["promoted"] == 0
    assert HostileDict.touched == 0


def test_stage2023_runtime_transaction_stats_rejects_hostile_mapping_hooks() -> None:
    HostileDict.touched = 0
    summary = replay_learning.empty_replay_summary()

    stats = project_runtime_transaction_stats(
        HostileDict({"promoted": True}), summary,
    )

    assert stats["runtime_committed"] is False
    assert stats["reason"] == "learning_result_unavailable"
    assert summary["runtime"] == 0
    assert HostileDict.touched == 0


def test_stage2023_safe_summary_count_rejects_hostile_int_without_hooks() -> None:
    HostileCount.touched = 0

    assert safe_summary_count(HostileCount()) == 0
    assert HostileCount.touched == 0


def test_stage2023_replay_learning_sources_have_no_backlog_mapping_snippets() -> None:
    learning_source = read_python_file(Path("Virus_Scan/models/replay/learning.py"))
    boundary_source = read_python_file(Path("Virus_Scan/models/replay/learning_boundaries.py"))

    forbidden_learning = (
        'payload.get("replay_payload_unavailable")',
        'learning_result.get("learned")',
        'learning_fields.items()',
        'results.values()',
        "totals.get(key, 0)",
    )
    for snippet in forbidden_learning:
        assert snippet not in learning_source
    assert "except RECOVERABLE_RUNTIME_ERRORS" not in boundary_source
    assert "int(value)" not in boundary_source
