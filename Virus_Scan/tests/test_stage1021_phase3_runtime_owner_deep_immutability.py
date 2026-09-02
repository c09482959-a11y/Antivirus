from __future__ import annotations

from typing import Any, cast

import pytest

from Virus_Scan.contracts.telemetry import record_detector_error
from Virus_Scan.runtime.detector_state import DetectorStateOwner
from Virus_Scan.runtime.events import RuntimeEvent
from Virus_Scan.runtime.fault_domains import FaultResult, RUNTIME_FAILURE
from Virus_Scan.runtime.ownership import RuntimeStateOwner
from Virus_Scan.runtime.path_runtime_state import PathRuntimeStateOwner
from Virus_Scan.runtime.scheduler_runtime_state import SchedulerRuntimeState
from Virus_Scan.runtime.state_domains import RuntimeDomainRegistry
from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot, record_failure


def test_stage1021_runtime_state_owner_detaches_nested_values() -> None:
    owner = RuntimeStateOwner()
    source = {"nested": {"items": ["original"]}}

    owner.set("payload", source, domain="runtime")
    source["nested"]["items"].append("mutated")

    snapshot = owner.snapshot()
    assert snapshot["payload"]["nested"]["items"] == ("original",)
    with pytest.raises(TypeError):
        snapshot["payload"]["nested"]["items"] += ("blocked",)

    view = owner.readonly_view()
    assert view.get("payload")["nested"]["items"] == ("original",)
    assert view.as_dict()["payload"]["nested"]["items"] == ["original"]


def test_stage1021_runtime_domain_registry_snapshots_are_deeply_immutable() -> None:
    registry = RuntimeDomainRegistry()
    source = {"children": ["one"]}

    registry.set("scheduler", "queue", source)
    source["children"].append("two")

    snapshot = registry.snapshot()
    assert snapshot["scheduler"]["queue"]["children"] == ("one",)
    with pytest.raises(TypeError):
        cast(Any, snapshot["scheduler"])["queue"] = {"children": []}


def test_stage1021_runtime_event_fields_are_detached_from_caller_owned_payload() -> None:
    fields = {"evidence": {"tags": ["initial"]}}
    event = RuntimeEvent(event_type="state_mutation", domain="runtime", message="published", fields=fields)
    fields["evidence"]["tags"].append("mutated")

    assert event.fields["evidence"]["tags"] == ("initial",)
    assert event.as_dict()["fields"]["evidence"]["tags"] == ["initial"]


def test_stage1021_path_runtime_owner_freezes_engine_context_at_configure_boundary() -> None:
    owner = PathRuntimeStateOwner()
    context = {"scores": {"renpy": [0.9]}}

    owner.configure_engine("auto", "renpy", context)
    context["scores"]["renpy"].append(0.1)

    snapshot = owner.snapshot()
    assert snapshot.scan_engine_hint_context["scores"]["renpy"] == (0.9,)


def test_stage1021_scheduler_runtime_state_freezes_stage_tables_and_cache_values() -> None:
    state = SchedulerRuntimeState()
    limits = {"raw": {"workers": [1]}}
    state.configure_worker_stage_tables(stage_limits=limits, stage_semaphores={})
    limits["raw"]["workers"].append(99)

    tables = state.stage_tables_snapshot()
    assert tables["stage_limits"]["raw"]["workers"] == (1,)

    result = {"tags": ["a"]}
    state.raw_stage_cache_put("sample", result)
    result["tags"].append("b")
    cached_result = state.raw_stage_cache_get("sample")
    assert cached_result is not None
    assert cached_result["tags"] == ("a",)
    assert state.raw_stage_cache_snapshot()["sample"]["tags"] == ("a",)


def test_stage1021_fault_result_detaches_nested_value_payload() -> None:
    source = {"evidence": {"tags": ["failure"]}}
    result = FaultResult(False, value=source, domain=RUNTIME_FAILURE)
    source["evidence"]["tags"].append("mutated")

    assert result.value["evidence"]["tags"] == ("failure",)
    assert result.materialized_value()["evidence"]["tags"] == ["failure"]

def test_stage1021_detector_state_records_context_as_owned_snapshot() -> None:
    owner = DetectorStateOwner()
    context = {"engine": {"scores": [0.1]}}

    owner.record("renpy", RuntimeError("boom"), context)
    context["engine"]["scores"].append(0.9)

    snapshot = owner.snapshot()
    assert snapshot[0]["context"]["engine"]["scores"] == [0.1]
    readonly = owner.readonly()
    assert readonly["errors"][0]["context"]["engine"]["scores"] == (0.1,)


def test_stage1021_record_detector_error_detaches_context_keywords() -> None:
    context = {"path": {"parts": ["a"]}}
    keyword_context = {"scores": [1]}

    record = record_detector_error("unity", "err", context, keyword_context=keyword_context)
    context["path"]["parts"].append("b")
    keyword_context["scores"].append(2)

    assert record["context"]["path"]["parts"] == ["a"]
    assert record["context"]["keyword_context"]["scores"] == [1]

def test_stage1021_failure_record_provenance_is_immutable_and_materializes_in_snapshot() -> None:
    clear_failure_records()
    context: dict[str, Any] = {"parent_chain": ["root"], "nested": {"tags": ["a"]}}
    record = record_failure("runtime", "phase3", RuntimeError("boom"), context=context)
    context["parent_chain"].append("mutated")
    context["nested"]["tags"].append("b")

    assert record.provenance["parent_chain"] == ("root",)
    with pytest.raises(TypeError):
        record.provenance["parent_chain"] += ("blocked",)  # type: ignore[index,operator]

    snapshot = failure_snapshot()
    assert snapshot["records"][0]["provenance"]["parent_chain"] == ["root"]
