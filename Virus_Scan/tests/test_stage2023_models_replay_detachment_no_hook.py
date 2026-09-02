from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.models.replay.detachment import (
    detach_replay_payload_mapping_with_errors,
    detach_replay_payload_value,
    replay_sequence_and_errors,
    safe_replay_text,
)


class HostileKey:
    touched = 0

    def __eq__(self, other):  # pragma: no cover - any call is the regression
        type(self).touched += 1
        raise AssertionError("caller-owned key equality hook executed")

    def __hash__(self) -> int:
        return 41

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned key text hook executed")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned key repr hook executed")

    def __format__(self, spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned key format hook executed")


class HostileReason:
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned reason text hook executed")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned reason repr hook executed")

    def __format__(self, spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned reason format hook executed")


class HostileMapping(Mapping):
    touched = 0

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned mapping iteration hook executed")

    def __len__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned mapping length hook executed")

    def __getitem__(self, key):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned mapping item hook executed")

    def items(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned mapping items hook executed")


def _reset() -> None:
    HostileKey.touched = 0
    HostileReason.touched = 0
    HostileMapping.touched = 0


def test_stage2023_replay_detachment_dict_keys_do_not_use_caller_equality_or_format() -> None:
    _reset()
    detached = detach_replay_payload_value({HostileKey(): "blocked", "safe": 1})

    assert detached["safe"] == 1
    assert any(key.startswith("<HostileKey>#") for key in detached)
    assert HostileKey.touched == 0


def test_stage2023_replay_error_projection_rejects_hostile_field_and_reason_without_hooks() -> None:
    _reset()
    clean, errors = replay_sequence_and_errors(
        [{"value": None, "unavailable_reason": HostileReason()}],
        HostileReason(),
    )

    assert clean == []
    assert errors == ["replay_payload:unsupported_replay_payload"]
    assert HostileReason.touched == 0


def test_stage2023_required_mapping_error_rejects_hostile_mapping_protocols() -> None:
    _reset()
    mapping, errors = detach_replay_payload_mapping_with_errors(
        HostileMapping(),
        HostileReason(),
        required_mapping=True,
    )

    assert mapping == {}
    assert errors == ["replay_payload:unsupported_replay_payload_mapping"]
    assert HostileMapping.touched == 0
    assert HostileReason.touched == 0


def test_stage2023_safe_replay_text_is_canonical_no_hook_text_owner() -> None:
    _reset()
    assert safe_replay_text(HostileReason()) == ""
    assert HostileReason.touched == 0

    source = read_python_file(Path("Virus_Scan/models/replay/detachment.py"))
    assert "_exact_replay_text" not in source
    assert "tuple(dict.items(value))" not in source
    assert 'f"{field}' not in source
