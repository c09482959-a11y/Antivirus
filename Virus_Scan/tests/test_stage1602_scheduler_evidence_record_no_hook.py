"""Stage1602 scheduler evidence record/collection no-hook regression tests."""
from __future__ import annotations

from collections.abc import Mapping
import json

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.records import SchedulerEvidenceBundle, build_scheduler_json_evidence_section, collect_scheduler_evidence


class HostileScalar:
    str_calls = 0
    repr_calls = 0
    bool_calls = 0
    eq_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("str hook called")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("repr hook called")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("bool hook called")

    def __eq__(self, other):
        type(self).eq_calls += 1
        raise RuntimeError("eq hook called")


class HostileEvidenceObject:
    evidence_property_calls = 0
    iter_calls = 0

    @property
    def evidence(self):
        type(self).evidence_property_calls += 1
        raise RuntimeError("evidence property called")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("iter hook called")


class HostileMapping(Mapping):
    iter_calls = 0
    items_calls = 0
    get_calls = 0
    contains_calls = 0

    def __getitem__(self, key):
        raise KeyError(key)

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("mapping iter hook called")

    def __len__(self):
        raise RuntimeError("mapping len hook called")

    def items(self):
        type(self).items_calls += 1
        raise RuntimeError("mapping items hook called")

    def get(self, key, default=None):
        type(self).get_calls += 1
        raise RuntimeError("mapping get hook called")

    def __contains__(self, key):
        type(self).contains_calls += 1
        raise RuntimeError("mapping contains hook called")


def _reset() -> None:
    HostileScalar.str_calls = 0
    HostileScalar.repr_calls = 0
    HostileScalar.bool_calls = 0
    HostileScalar.eq_calls = 0
    HostileEvidenceObject.evidence_property_calls = 0
    HostileEvidenceObject.iter_calls = 0
    HostileMapping.iter_calls = 0
    HostileMapping.items_calls = 0
    HostileMapping.get_calls = 0
    HostileMapping.contains_calls = 0


def test_stage1602_scheduler_evidence_record_constructor_rejects_hostile_fields_without_hooks() -> None:
    _reset()
    hostile = HostileScalar()

    record = SchedulerEvidenceRecord(
        stage=hostile,
        state=hostile,
        error_category=hostile,
        message=hostile,
        path=hostile,
        retry_state_affected=hostile,
        timeout_state_affected=hostile,
        fatal=hostile,
    )
    payload = record.as_dict()

    assert payload["stage"] == "scheduler"
    assert payload["state"] == "degraded"
    assert payload["fatal"] is False
    assert payload["context"]["stage_materialization"]["scheduler_evidence_field_rejected"] is True
    assert payload["context"]["fatal_materialization"]["reason"] == "scheduler_evidence_bool_rejected"
    json.dumps(payload, sort_keys=True)
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1602_scheduler_evidence_from_mapping_rejects_hostile_values_without_hooks() -> None:
    _reset()
    hostile = HostileScalar()

    record = SchedulerEvidenceRecord.from_mapping({
        "stage": hostile,
        "error_category": "queue_failure",
        "path": hostile,
        "fatal": hostile,
        "context": {"raw": hostile},
    })
    payload = record.as_dict()

    assert payload["stage"] == "scheduler"
    assert payload["error_category"] == "queue_failure"
    assert payload["context"]["path_materialization"]["scheduler_evidence_field_rejected"] is True
    assert payload["context"]["raw"]["unsupported_scheduler_value"] is True
    json.dumps(payload, sort_keys=True)
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.eq_calls == 0


def test_stage1602_collect_scheduler_evidence_rejects_unknown_object_without_iter_or_property_hooks() -> None:
    _reset()

    records = collect_scheduler_evidence(HostileEvidenceObject())
    section = build_scheduler_json_evidence_section(records)

    assert records
    assert records[0].error_category == "scheduler_evidence_source_rejected"
    assert section["scheduler_status"] == "fatal"
    assert section["evidence"][0]["context"]["unsupported_scheduler_evidence_source"]["unsupported_scheduler_value"] is True
    json.dumps(section, sort_keys=True)
    assert HostileEvidenceObject.evidence_property_calls == 0
    assert HostileEvidenceObject.iter_calls == 0


def test_stage1602_collect_scheduler_evidence_rejects_mapping_subclass_without_mapping_hooks() -> None:
    _reset()

    records = collect_scheduler_evidence(HostileMapping())
    payload = records[0].as_dict()

    assert payload["error_category"] == "scheduler_evidence_source_rejected"
    assert payload["context"]["unsupported_scheduler_evidence_source"]["unsupported_scheduler_value"] is True
    json.dumps(payload, sort_keys=True)
    assert HostileMapping.iter_calls == 0
    assert HostileMapping.items_calls == 0
    assert HostileMapping.get_calls == 0
    assert HostileMapping.contains_calls == 0


def test_stage1602_scheduler_evidence_bundle_from_mapping_rejects_mapping_subclass_without_hooks() -> None:
    _reset()

    bundle = SchedulerEvidenceBundle.from_mapping(HostileMapping())
    section = bundle.as_dict()

    assert bundle.records
    assert section["scheduler_status"] == "fatal"
    assert section["evidence"][0]["error_category"] == "scheduler_evidence_mapping_rejected"
    assert HostileMapping.iter_calls == 0
    assert HostileMapping.items_calls == 0
    assert HostileMapping.get_calls == 0
    assert HostileMapping.contains_calls == 0
