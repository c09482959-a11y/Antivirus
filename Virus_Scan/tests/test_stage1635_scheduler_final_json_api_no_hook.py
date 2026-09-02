from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.scheduler.api import final_json
from Virus_Scan.scheduler.api.final_json import (
    attach_scheduler_final_json_fields,
    enrich_scheduler_final_json_results,
)


class HostileSchedulerMapping(Mapping):
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("bool hook must not run")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("iter hook must not run")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("len hook must not run")

    def __getitem__(self, key):
        type(self).touched += 1
        raise RuntimeError("getitem hook must not run")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("items hook must not run")


class HostileSchedulerRecord:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("bool hook must not run")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("str hook must not run")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("repr hook must not run")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("iter hook must not run")


def _error_categories(section):
    return {item.get("error_category") for item in section["scheduler"]["evidence"]}


def test_stage1635_attach_scheduler_final_json_rejects_hostile_mapping_without_hooks():
    HostileSchedulerMapping.touched = 0

    section = attach_scheduler_final_json_fields(HostileSchedulerMapping())

    assert HostileSchedulerMapping.touched == 0
    assert section["scheduler_status"] == "fatal"
    assert "scheduler_final_json_record_rejected" in _error_categories(section)
    evidence = section["scheduler"]["evidence"][0]
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_record"] is True


def test_stage1635_enrich_scheduler_results_rejects_hostile_results_mapping_without_hooks():
    HostileSchedulerMapping.touched = 0

    enriched = enrich_scheduler_final_json_results(HostileSchedulerMapping())

    assert HostileSchedulerMapping.touched == 0
    section = enriched["__scheduler_results_unavailable__"]
    assert section["scheduler_status"] == "fatal"
    assert "scheduler_final_json_results_rejected" in _error_categories(section)


def test_stage1635_enrich_scheduler_results_rejects_hostile_record_value_without_hooks():
    HostileSchedulerRecord.touched = 0

    enriched = enrich_scheduler_final_json_results({"bad.bin": HostileSchedulerRecord()})

    assert HostileSchedulerRecord.touched == 0
    section = enriched["bad.bin"]
    assert section["scheduler_status"] == "fatal"
    assert "scheduler_final_json_result_record_rejected" in _error_categories(section)


def test_stage1635_attach_scheduler_final_json_preserves_clean_exact_dict_behavior():
    record = {"path": "clean.bin", "classification": "Benign", "score": 0.0}

    section = attach_scheduler_final_json_fields(record)

    assert section["path"] == "clean.bin"
    assert section["classification"] == "Benign"
    assert section["score"] == 0.0
    assert "scheduler" not in section


def test_stage1635_architecture_scheduler_final_json_api_has_no_legacy_truthy_dict_materialization():
    source = read_python_file(Path("Virus_Scan/scheduler/api/final_json.py"))
    forbidden = (
        "dict(record or {})",
        "(results or {}).items()",
        "results or {}",
        "dict(record)",
    )
    for marker in forbidden:
        assert marker not in source


def test_stage1825_enrich_scheduler_results_uses_exact_fallback_key_without_path_hooks():
    HostileSchedulerRecord.touched = 0

    hostile_key = HostileSchedulerRecord()
    enriched = enrich_scheduler_final_json_results({hostile_key: {"path": "clean.bin"}})

    assert HostileSchedulerRecord.touched == 0
    assert "unsupported_scheduler_result_key_0" in enriched


def test_stage1825_scheduler_api_failure_field_name_rejects_non_text_without_hooks():
    HostileSchedulerRecord.touched = 0

    section = final_json._scheduler_api_failure_fields(
        HostileSchedulerRecord(),
        field_name=HostileSchedulerRecord(),
    )

    assert HostileSchedulerRecord.touched == 0
    assert "scheduler_api_field_rejected" in _error_categories(section)
    assert "scheduler_api_field" in section["scheduler"]["evidence"][0]["context"]
