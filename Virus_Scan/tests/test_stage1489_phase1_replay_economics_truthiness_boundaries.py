from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Iterator

from Virus_Scan.models.replay_economics import (
    ReplayEconomicsConfig,
    replay_should_retain,
)
from Virus_Scan.models.api import replay_economics_contracts


class HostileBool:
    def __bool__(self) -> bool:  # pragma: no cover - failure path assertion
        raise RuntimeError("truthiness probe must not be used")

    def __str__(self) -> str:  # pragma: no cover - failure path assertion
        raise RuntimeError("string coercion must not be used after unsafe truthiness")


class HostileReplayMapping(Mapping[str, Any]):
    def __getitem__(self, key: str) -> Any:
        if key in {"path", "file", "replay_divergence"}:
            return HostileBool()
        if key == "score":
            return 0
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(("path", "file", "score", "replay_divergence"))

    def __len__(self) -> int:
        return 4

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


class UnreadableReplayMapping(Mapping[str, Any]):
    def __getitem__(self, key: str) -> Any:
        raise RuntimeError("mapping read failed")

    def __iter__(self) -> Iterator[str]:
        return iter(("path",))

    def __len__(self) -> int:
        return 1

    def get(self, key: str, default: Any = None) -> Any:
        raise RuntimeError("mapping get failed")


def test_stage1489_replay_economics_owner_retains_hostile_truthiness_payloads() -> None:
    result = HostileReplayMapping()
    config = ReplayEconomicsConfig(sample_modulo=999_983, divergence_always_keep=True)

    assert replay_should_retain(result, index=1, config=config) is True


def test_stage1489_replay_economics_owner_retains_unreadable_payloads() -> None:
    result = UnreadableReplayMapping()
    config = ReplayEconomicsConfig(sample_modulo=999_983, divergence_always_keep=True)

    assert replay_should_retain(result, index=1, config=config) is True


def test_stage1489_replay_economics_public_contract_preserves_owner_boundary() -> None:
    assert replay_economics_contracts.replay_should_retain(HostileReplayMapping()) is True
    assert replay_economics_contracts.replay_should_retain(UnreadableReplayMapping()) is True
