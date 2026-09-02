from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from Virus_Scan.runtime.profile_scoring_state import ProfileScoringState
from Virus_Scan.runtime.fault_domains import RUNTIME_FAILURE, FaultResult
from Virus_Scan.runtime.structured_failures import clear_failure_records, record_failure
from Virus_Scan.runtime.scan_integrity_state import RuntimeScanIntegrityState
from Virus_Scan.runtime.scheduler_runtime_state import SchedulerRuntimeState
from Virus_Scan.runtime.yara_rules_state import YaraLightSnapshot, YaraRulesSnapshot, YaraRulesState


def test_stage1019_scheduler_profile_policy_snapshot_is_immutable() -> None:
    state = SchedulerRuntimeState()
    snapshot = state.configure_profile_policy(
        defer_profile_writes=True,
        profile_flush_every=2,
        bulk_profile_flush_every=5,
    )

    assert snapshot.defer_profile_writes is False
    assert snapshot.profile_flush_every == 1
    with pytest.raises(FrozenInstanceError):
        snapshot.profile_flush_every = 99


def test_stage1019_fault_result_is_immutable_result_contract() -> None:
    result = FaultResult(False, value={"nested": ["owned"]}, error=RuntimeError("boom"), domain=RUNTIME_FAILURE)

    assert result.tag == "failure_domain_runtime"
    with pytest.raises(FrozenInstanceError):
        result.ok = True


def test_stage1019_yara_rule_snapshots_are_immutable_and_state_replaces_them() -> None:
    state = YaraRulesState()

    state.mark_light_import_error()
    light = state.light_snapshot()
    assert isinstance(light, YaraLightSnapshot)
    assert light.import_error_logged is True
    with pytest.raises(FrozenInstanceError):
        light.ok = True

    state.set_light_rules(rules="compiled-light", ok=True, loaded_count=3)
    followup_light = state.light_snapshot()
    assert followup_light.rules == "compiled-light"
    assert followup_light.ok is True
    assert followup_light.loaded_count == 3
    assert followup_light.import_error_logged is True

    state.set_primary_rules("compiled-primary", source_path="rules.yar", loaded_count=7)
    primary = state.primary_snapshot()
    assert isinstance(primary, YaraRulesSnapshot)
    assert primary.rules == "compiled-primary"
    assert primary.source_path == "rules.yar"
    assert primary.loaded_count == 7
    with pytest.raises(FrozenInstanceError):
        primary.loaded_count = 0

    state.clear_primary_rules()
    assert state.primary_snapshot().rules is None
    assert state.primary_snapshot().loaded_count == 7


def test_stage1019_scan_integrity_state_detaches_caller_owned_nested_metadata() -> None:
    state = RuntimeScanIntegrityState()
    metadata = {"stage": "fast", "nested": {"tags": ["a"]}}

    state.set("sample", metadata)
    metadata["nested"]["tags"].append("mutated")

    first = state.get("sample")
    assert first["nested"]["tags"] == ("a",)
    first["nested"] = {"tags": ["changed"]}
    second = state.get("sample")
    assert second["nested"]["tags"] == ("a",)


def test_stage1019_profile_scoring_state_detaches_frozen_profile_snapshot() -> None:
    state = ProfileScoringState()
    profile = {"renpy": {"weights": {"tag": [1.0]}}}

    returned = state.freeze(profile)
    profile["renpy"]["weights"]["tag"].append(99.0)
    returned["renpy"]["weights"]["tag"].append(42.0)

    frozen_profile = state.get_profile("renpy")
    assert frozen_profile == {"weights": {"tag": [1.0]}}

    snapshot = state.snapshot()
    snapshot["renpy"]["weights"]["tag"].append(100.0)
    assert state.get_profile("renpy") == {"weights": {"tag": [1.0]}}


def test_stage1019_profile_scoring_state_clear_replaces_frozen_snapshot() -> None:
    state = ProfileScoringState()
    state.freeze({"renpy": {"weights": {"tag": [1.0]}}})

    state.clear()

    assert state.is_frozen() is False
    assert state.snapshot() == {}
    assert state.get_profile("renpy") is None


def test_stage1019_failure_record_is_immutable_and_store_updates_by_replacement() -> None:
    clear_failure_records()
    first = record_failure("runtime", "immutable_record", RuntimeError("one"))
    second = record_failure("runtime", "immutable_record", RuntimeError("two"))

    assert first.count == 1
    assert second.count == 2
    assert second.message == "two"
    with pytest.raises(FrozenInstanceError):
        second.count = 99
