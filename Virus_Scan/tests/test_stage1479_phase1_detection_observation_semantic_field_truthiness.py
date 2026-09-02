from __future__ import annotations

from collections.abc import Mapping

import pytest

from Virus_Scan.contracts.detection_observation import DetectionObservation
from Virus_Scan.models.markov.flow import canonical_behavior_flow


class HostileTruthyText:
    def __init__(self, text: str) -> None:
        self._text = text

    def __bool__(self) -> bool:  # pragma: no cover - failure proves boundary bug
        raise RuntimeError("caller-owned truthiness executed")

    def __str__(self) -> str:
        raise RuntimeError("caller-owned __str__ executed")


class HostileMapping(Mapping):
    def __init__(self, data: dict[str, object]) -> None:
        self._data = data

    def __getitem__(self, key: object) -> object:
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self) -> int:  # pragma: no cover - failure proves boundary bug
        raise RuntimeError("caller-owned mapping truthiness executed")

    def get(self, key: object, default: object = None) -> object:
        return self._data.get(key, default)


def test_detection_observation_rejects_non_builtin_semantic_tag_without_hooks() -> None:
    with pytest.raises((TypeError, ValueError)):
        DetectionObservation.from_value({"tag": HostileTruthyText("api_loadurl")})


def test_detection_observation_rejects_legacy_fallback_fields_without_hooks() -> None:
    with pytest.raises((TypeError, ValueError)):
        DetectionObservation.from_value(
            {"tag": HostileTruthyText(""), "behavior": HostileTruthyText("api_eval")}
        )


def test_markov_single_custom_mapping_observation_is_rejected_without_hooks() -> None:
    flow = canonical_behavior_flow(HostileMapping({"tag": HostileTruthyText("api_loadurl")}))

    assert flow == ()
