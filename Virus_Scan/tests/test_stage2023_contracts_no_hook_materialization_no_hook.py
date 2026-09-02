"""Stage 2023 canonical no-hook materialization remediation proofs."""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

import Virus_Scan.contracts.no_hook_materialization as materialization


class HostileReasonPrefix:
    touched = 0

    def __str__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("reason prefix str hook called")

    def __repr__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("reason prefix repr hook called")

    def __format__(self, _format_spec):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("reason prefix format hook called")

    def __bool__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("reason prefix bool hook called")


class HostileIndex:
    touched = 0

    def __str__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("index str hook called")

    def __repr__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("index repr hook called")

    def __format__(self, _format_spec):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("index format hook called")

    def __int__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("index int hook called")


class HostileInstanceDict:
    touched = 0

    def __getattribute__(self, _name):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("instance getattr hook called")


class HostileDictSubclass(dict):
    items_calls = 0

    def items(self):  # pragma: no cover - test fails if invoked
        type(self).items_calls += 1
        raise RuntimeError("items hook called")


def _reset() -> None:
    HostileReasonPrefix.touched = 0
    HostileIndex.touched = 0
    HostileInstanceDict.touched = 0
    HostileDictSubclass.items_calls = 0


def test_stage2023_reason_prefix_and_json_key_index_do_not_invoke_hostile_formatting_hooks() -> None:
    _reset()
    prefix = HostileReasonPrefix()
    index = HostileIndex()

    materialized = materialization.no_hook_materialize([1, 2], reason_prefix=prefix, max_items=1)  # type: ignore[arg-type]
    key, reason = materialization.no_hook_json_key("", index, prefix=prefix)  # type: ignore[arg-type]
    mapping_failure = materialization.materialize_mapping_no_hook([], context=prefix)  # type: ignore[arg-type]

    assert materialized["unavailable_reason"] == "json_sequence_size_limit_exceeded"
    assert key == "empty_non_materializable_key_0"
    assert reason == "blank_json_mapping_key"
    assert mapping_failure["unavailable_reason"] == "non_materializable_json_mapping"
    assert HostileReasonPrefix.touched == 0
    assert HostileIndex.touched == 0


def test_stage2023_status_helpers_preserve_rejection_reason_without_owner_hooks() -> None:
    _reset()

    instance_data, instance_reason = materialization.no_hook_plain_instance_dict_status(HostileInstanceDict())
    mapping_items, mapping_reason = materialization.no_hook_mapping_items_status(
        HostileDictSubclass({"safe": "value"}),
        allow_dict_subclass=True,
    )
    proxy_items, proxy_reason = materialization.no_hook_mapping_items_status(MappingProxyType({"safe": "value"}))

    assert instance_data is None
    assert instance_reason == "custom_getattribute"
    assert mapping_items is None
    assert mapping_reason == "dict_subclass_overrides_boundary_methods"
    assert proxy_items == (("safe", "value"),)
    assert proxy_reason == ""
    assert HostileInstanceDict.touched == 0
    assert HostileDictSubclass.items_calls == 0


def test_stage2023_no_hook_materialization_removes_proven_unsafe_source_shapes() -> None:
    source = Path(materialization.__file__).read_text(encoding="utf-8")
    lines = source.splitlines()

    for snippet in (
        "return tuple(dict.items(value))",
        "return tuple(dict.items(backing))",
        'f"empty_{prefix}_{index}"',
        'f"{prefix}_{index}"',
        'f"{reason_prefix}_depth_limit_exceeded"',
        'f"non_finite_{reason_prefix}_number"',
        'f"{reason_prefix}_bytes_encode_failed"',
        'f"{reason_prefix}_mapping_materialization_failed"',
        'f"{reason_prefix}_mapping_size_limit_exceeded"',
        'f"{reason_prefix}_key"',
        'f"{key_text}#{index}"',
        'f"{reason_prefix}_sequence_size_limit_exceeded"',
        'f"{reason_prefix}_set_size_limit_exceeded"',
        'f"{reason_prefix}_dataclass_field_unavailable"',
        'f"non_materializable_{reason_prefix}_value"',
        'f"non_materializable_{reason_prefix}_mapping"',
        'f"{no_hook_type_name(value)}:json_sort_unavailable"',
    ):
        assert snippet not in source

    for line_number, line in enumerate(lines):
        if not line.strip().startswith("except "):
            continue
        for following in lines[line_number + 1 :]:
            if following.strip() == "":
                continue
            assert following.strip() not in {"return False", "return None"}
            break
