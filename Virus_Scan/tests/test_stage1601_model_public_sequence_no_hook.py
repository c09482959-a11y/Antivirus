"""Stage1601: model public sequence boundaries reject unknown iterables/mappings."""
from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.models.api.adaptive_signals import public_adaptive_event_sequence_with_reason
from Virus_Scan.models.api.profile_learning_contracts import behavior_vector_from_scan
from Virus_Scan.models.api.temporal_contracts import transition_probability_overlay


class HostilePublicIterable:
    touched = 0

    def __bool__(self):  # pragma: no cover - failure proves truthiness returned
        type(self).touched += 1
        raise AssertionError("do not call bool")

    def __iter__(self):  # pragma: no cover - failure proves iteration returned
        type(self).touched += 1
        raise AssertionError("do not call iter")

    def __len__(self):  # pragma: no cover - failure proves len returned
        type(self).touched += 1
        raise AssertionError("do not call len")


class HostilePublicMapping(Mapping):
    touched = 0

    def __iter__(self):  # pragma: no cover - failure proves mapping iteration returned
        type(self).touched += 1
        raise AssertionError("do not call mapping iter")

    def __len__(self):  # pragma: no cover - failure proves mapping len returned
        type(self).touched += 1
        raise AssertionError("do not call mapping len")

    def __getitem__(self, key):  # pragma: no cover - failure proves mapping getitem returned
        type(self).touched += 1
        raise AssertionError("do not call mapping getitem")


def _reset() -> None:
    HostilePublicIterable.touched = 0
    HostilePublicMapping.touched = 0


def test_adaptive_public_event_sequence_rejects_unknown_iterable_and_mapping_without_hooks() -> None:
    _reset()

    values, reason = public_adaptive_event_sequence_with_reason(HostilePublicIterable())
    assert values == ()
    assert reason == "non_iterable_adaptive_public_sequence"

    values, reason = public_adaptive_event_sequence_with_reason(HostilePublicMapping())
    assert values == ()
    assert reason == "unsupported_adaptive_public_mapping_sequence"

    assert HostilePublicIterable.touched == 0
    assert HostilePublicMapping.touched == 0


def test_profile_learning_public_sequence_rejects_unknown_iterable_and_mapping_without_hooks() -> None:
    _reset()

    iterable_record = behavior_vector_from_scan("renpy", "sample.rpy", HostilePublicIterable())
    mapping_record = behavior_vector_from_scan("renpy", "sample.rpy", HostilePublicMapping())

    assert iterable_record["ready"] is False
    assert iterable_record["degraded"] is True
    assert iterable_record["unavailable_reason"] == "non_iterable_profile_learning_public_sequence"
    assert mapping_record["ready"] is False
    assert mapping_record["degraded"] is True
    assert mapping_record["unavailable_reason"] == "unsupported_profile_learning_public_mapping_sequence"
    assert HostilePublicIterable.touched == 0
    assert HostilePublicMapping.touched == 0


def test_temporal_public_sequence_rejects_unknown_iterable_and_mapping_without_hooks() -> None:
    _reset()

    iterable_record = transition_probability_overlay(tags=HostilePublicIterable())
    mapping_record = transition_probability_overlay(tags=HostilePublicMapping())

    assert iterable_record["ready"] is False
    assert iterable_record["degraded"] is True
    assert iterable_record["unavailable_reason"] == "non_iterable_temporal_public_sequence"
    assert mapping_record["ready"] is False
    assert mapping_record["degraded"] is True
    assert mapping_record["unavailable_reason"] == "unsupported_temporal_public_mapping_sequence"
    assert HostilePublicIterable.touched == 0
    assert HostilePublicMapping.touched == 0
