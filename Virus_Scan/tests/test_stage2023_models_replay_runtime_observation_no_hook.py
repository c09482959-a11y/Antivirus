"""Replay runtime telemetry is a no-hook projection of the committed transaction."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Iterator

from Virus_Scan.models.replay.transaction_projection import project_runtime_transaction_stats
from Virus_Scan.tests.support.profile_learning import (
    accepted_learning_request,
    accepted_runtime_transaction_result,
)
from Virus_Scan.tests.support.static_inventory import read_python_file


class HostileMapping(Mapping):
    touched = 0

    def _touch(self):
        type(self).touched += 1
        raise AssertionError("caller-owned mapping hook was invoked")

    def __contains__(self, _key):  # pragma: no cover - must not execute
        return self._touch()

    def __getitem__(self, _key):  # pragma: no cover - must not execute
        return self._touch()

    def __iter__(self) -> Iterator[str]:  # pragma: no cover - must not execute
        return self._touch()

    def __len__(self) -> int:  # pragma: no cover - must not execute
        return self._touch()

    def get(self, *_args, **_kwargs):  # pragma: no cover - must not execute
        return self._touch()


class HostileText:
    touched = 0

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned truthiness hook was invoked")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned text hook was invoked")


def _accepted_result() -> dict[str, object]:
    request = accepted_learning_request(
        Path("sample.rpy"), flow=("decode", "execute"),
        observation_id="stage2023-runtime-transaction-projection",
    )
    return accepted_runtime_transaction_result(request)


def test_stage2023_runtime_transaction_projection_rejects_hostile_mapping_without_hooks() -> None:
    HostileMapping.touched = 0
    summary = {"runtime": 0}

    stats = project_runtime_transaction_stats(HostileMapping(), summary)

    assert stats == {
        "runtime_committed": False,
        "reason": "learning_result_unavailable",
        "model_updates_authorized": False,
    }
    assert summary["runtime"] == 0
    assert HostileMapping.touched == 0


def test_stage2023_runtime_transaction_projection_rejects_hostile_digest_without_hooks() -> None:
    HostileText.touched = 0
    result = _accepted_result()
    result["source_record_digest"] = HostileText()

    stats = project_runtime_transaction_stats(
        result, {"runtime": 0},
    )

    assert stats["runtime_committed"] is False
    assert stats["reason"] == "source_record_digest_mismatch"
    assert HostileText.touched == 0


def test_stage2023_runtime_transaction_projection_rejects_hostile_target_status_without_hooks() -> None:
    HostileMapping.touched = 0
    result = _accepted_result()
    result["target_status"] = HostileMapping()

    stats = project_runtime_transaction_stats(
        result, {"runtime": 0},
    )

    assert stats["runtime_committed"] is False
    assert stats["reason"] == "runtime_target_status_unavailable"
    assert HostileMapping.touched == 0


def test_stage2023_runtime_observation_execution_owner_is_deleted() -> None:
    source = read_python_file(Path("Virus_Scan/models/replay/learning.py"))

    assert not Path("Virus_Scan/models/replay/runtime_observation.py").exists()
    for snippet in (
        "replay_runtime_model_observation",
        "update_markov_model(",
        "commit_temporal_runtime_learning(",
        "commit_temporal_learning_request(",
    ):
        assert snippet not in source
