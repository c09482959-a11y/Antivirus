from __future__ import annotations

from Virus_Scan.publication.json_finalization.success_fields import compact_success_routing_fields
from Virus_Scan.publication.json_finalization.truthiness import (
    boolean_field_true,
    iterable_values_without_truthiness,
    string_or_empty,
)


class HostileStringSubclass(str):
    touched = 0

    def strip(self, *args, **kwargs):
        HostileStringSubclass.touched += 1
        raise RuntimeError("strip must not execute")

    def lower(self, *args, **kwargs):
        HostileStringSubclass.touched += 1
        raise RuntimeError("lower must not execute")

    def __str__(self):
        HostileStringSubclass.touched += 1
        raise RuntimeError("__str__ must not execute")

    def __repr__(self):
        HostileStringSubclass.touched += 1
        raise RuntimeError("__repr__ must not execute")


def test_stage1638_truthiness_helpers_reject_string_subclasses_without_hooks():
    HostileStringSubclass.touched = 0
    hostile = HostileStringSubclass(" true ")

    assert boolean_field_true(hostile) is False
    assert string_or_empty(hostile) == ""
    assert iterable_values_without_truthiness(hostile) == []
    assert HostileStringSubclass.touched == 0


def test_stage1638_truthiness_helpers_preserve_exact_primitive_strings():
    assert boolean_field_true(" true ") is True
    assert boolean_field_true("ON") is True
    assert string_or_empty("value") == "value"
    assert iterable_values_without_truthiness("tag") == ["tag"]


def test_stage1638_compact_routing_boolean_fields_do_not_execute_hostile_string_subclass():
    HostileStringSubclass.touched = 0
    hostile = HostileStringSubclass("true")
    record = {
        "cross_engine_artifact": hostile,
        "engine_mismatch": hostile,
        "learning_allowed": hostile,
        "routing_evidence": {},
    }
    context = {"tags": [], "record_extension": "bin", "extension_mismatch_evidence": []}

    fields = compact_success_routing_fields(record, context)

    assert fields["cross_engine_artifact"] is False
    assert fields["engine_mismatch"] is False
    assert fields["learning_allowed"] is False
    assert HostileStringSubclass.touched == 0
