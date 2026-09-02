"""Stage 1487: replay transaction telemetry rejects caller-owned mappings."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Iterator

from Virus_Scan.models.replay.transaction_projection import project_runtime_transaction_stats


class HostilePresencePayload(Mapping):
    touched = 0

    def __getitem__(self, key):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError(key)

    def __iter__(self) -> Iterator[str]:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("iteration")

    def __len__(self) -> int:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("length")

    def __contains__(self, key):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError(key)

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("truthiness")


class HostileGetPayload(HostilePresencePayload):
    def get(self, key, default=None):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError(key)


def test_stage1487_runtime_transaction_projection_bounds_hostile_key_presence_probe() -> None:
    HostilePresencePayload.touched = 0
    stats = project_runtime_transaction_stats(
        HostilePresencePayload(), {"runtime": 0},
    )
    assert stats["runtime_committed"] is False
    assert stats["reason"] == "learning_result_unavailable"
    assert HostilePresencePayload.touched == 0


def test_stage1487_runtime_transaction_projection_bounds_hostile_optional_gets() -> None:
    HostileGetPayload.touched = 0
    stats = project_runtime_transaction_stats(
        HostileGetPayload(), {"runtime": 0},
    )
    assert stats["runtime_committed"] is False
    assert stats["reason"] == "learning_result_unavailable"
    assert HostileGetPayload.touched == 0
