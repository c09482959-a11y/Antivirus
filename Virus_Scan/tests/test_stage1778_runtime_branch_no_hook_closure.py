"""Stage1778 runtime branch root-cause closure regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.runtime_model_state import current_runtime_model_record
from Virus_Scan.tests.support.static_inventory import parse_python_file, python_files_under


import ast
from collections import Counter, defaultdict
import os
from pathlib import Path

import pytest

from Virus_Scan.runtime.config import ArchiveScanLimits
from Virus_Scan.contracts.markov_learning import (
    markov_event_transition_key,
    markov_global_context_key,
)
from Virus_Scan.runtime import model_state


def _markov_event_key():
    return markov_event_transition_key(
        context_key=markov_global_context_key(), previous_stage="asset", source_event="download",
    )
from Virus_Scan.runtime.causal_event_stream import (
    CausalEvent,
    EventBus,
    ReplayTombstone,
    WorkloadEventBudget,
)
from Virus_Scan.runtime.architecture_governance import (
    causal_architecture_visualization,
)
from Virus_Scan.runtime.cleanup_invariants import RuntimeCleanupSnapshot
from Virus_Scan.runtime.cluster_state import (
    RuntimeClusterState,
    configure_runtime_cluster_state,
    runtime_cluster_state_to_json,
)
from Virus_Scan.runtime.determinism import (
    deterministic_path_inventory,
    deterministic_scan_path_inventory,
)
from Virus_Scan.runtime.detector_state import DetectorStateOwner
from Virus_Scan.runtime.engine_hint_runtime import detect_startup_engine_context
from Virus_Scan.runtime.resource_economics import (
    ArchiveComplexityScore,
    ExtractionEconomics,
    WorkComplexitySignal,
    adaptive_reprice_cost,
    confidence_inertia,
)
from Virus_Scan.runtime.resource_quotas import (
    ExtractionQuotaTracker,
    ResourceQuotaExceeded,
    RuntimeBudget,
)
from Virus_Scan.runtime.replay_introspection import (
    build_replay_graph,
    validate_replay_integrity,
    why_event,
)
from Virus_Scan.runtime.runtime_flags import RuntimeFlagOwner
from Virus_Scan.runtime.graph_state import (
    add_graph_edge_owned,
    decay_graph_weights_owned,
    graph_node_snapshots,
    graph_owner,
    graph_snapshot,
    prune_graph_owned,
    reset_graph_state,
    update_graph_node_owned,
)
from Virus_Scan.runtime.governance_read_model import build_governance_read_model
from Virus_Scan.runtime.fault_domains import failure_tag
from Virus_Scan.runtime.ownership import RuntimeStateOwner
from Virus_Scan.runtime.provenance import ProvenanceLedger
from Virus_Scan.runtime.readonly import ReadonlyRuntimeView
from Virus_Scan.runtime.causal_snapshots import CausalReplaySnapshot, build_causal_snapshot
from Virus_Scan.runtime.causal_text import causal_text
from Virus_Scan.runtime.emergent_simulation import immutable_orchestration_invariants
from Virus_Scan.runtime.entropy_governance import audit_entropy
from Virus_Scan.runtime.event_contracts import EventContract
from Virus_Scan.runtime.governance_invariants import (
    CircuitBreakerState,
    RuntimeInvariantReport,
)
from Virus_Scan.runtime.governance_planes import GovernancePlane
from Virus_Scan.runtime.mutation_coordinator import RuntimeRoot
from Virus_Scan.runtime.replay_introspection import ReplayIntegrityReport
from Virus_Scan.runtime.runtime_debt import WorkloadDebt
from Virus_Scan.runtime.scan_dependencies import (
    ScanDependencyRegistry,
    intrastage_enabled,
    read_file_bytes,
    scan_strings,
    stage_parallel_workers,
)
from Virus_Scan.runtime.scan_run_guard import acquire_parent_scan_guard
from Virus_Scan.runtime.structured_failures import (
    FailureRecord,
    FailureRecorderInternalTrail,
    FailureRecordStore,
)
from Virus_Scan.runtime.telemetry import RuntimeTelemetry
from Virus_Scan.runtime.stability_policy import StabilizationDecision
from Virus_Scan.runtime.stabilization_arbitration import ArbitrationResult
from Virus_Scan.runtime.yara_rules_state import YaraRulesSnapshot


class _HostileNumber:
    touched = 0

    def __bool__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not coerce truth")

    def __int__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not coerce integer")

    def __float__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not coerce float")

    def __str__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not stringify")

    def __repr__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not repr")


class _HostilePath:
    touched = 0

    def __bool__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not coerce truth")

    def __fspath__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not call fspath")

    def __str__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not stringify")


class _HostileArgs:
    touched = 0

    @property
    def dir(self):  # pragma: no cover - regression asserts no access
        type(self).touched += 1
        raise AssertionError("do not traverse dir property")

    @property
    def output(self):  # pragma: no cover - regression asserts no access
        type(self).touched += 1
        raise AssertionError("do not traverse output property")


class _HostileGraphNode:
    touched = 0

    def __hash__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not hash caller-owned node")

    def __eq__(self, other):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not compare caller-owned node")

    def __str__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not stringify caller-owned node")

    def __repr__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not repr caller-owned node")

    def __format__(self, format_spec):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not format caller-owned node")

    def __lt__(self, other):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not order caller-owned node")


class _HostileMapping(dict):
    touched = 0

    def items(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not traverse caller-owned mapping")

    def __iter__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not iterate caller-owned mapping")


class _HostileSequence:
    touched = 0

    def __iter__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("do not iterate caller-owned sequence")


class _HostileBus:
    touched = 0

    def __getattribute__(self, name):  # pragma: no cover - asserts no access
        type(self).touched += 1
        raise AssertionError("do not inspect caller-owned event bus")


def _configure_model_state():
    transitions = defaultdict(Counter)
    tags = defaultdict(int)
    pairs = defaultdict(int)
    filetypes = defaultdict(Counter)
    model_state.configure_runtime_model_state(
        transition_counts=transitions,
        global_tag_baseline=tags,
        global_tag_pair_baseline=pairs,
        filetype_baseline=filetypes,
    )
    return transitions, tags, pairs, filetypes


def test_stage1778_model_loader_missing_section_rejects_and_preserves_owned_state() -> None:
    transitions, tags, pairs, filetypes = _configure_model_state()
    transitions[_markov_event_key()]["exec"] = 2
    tags["download"] = 3
    pairs[("download", "exec")] = 4
    filetypes[".bin"]["download"] = 5
    record = current_runtime_model_record({"global_tag_baseline": {"persist": 7}})
    record.pop("transition_counts")
    result = model_state.load_runtime_model_baselines(record)
    assert result["loaded"] is False
    assert result["reason"] == "runtime_model_snapshot_fields_missing"
    assert model_state.runtime_transition_counter_snapshot(_markov_event_key()) == {"exec": 2}
    assert model_state.runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE") == {"download": 3}
    assert model_state.runtime_model_mapping_snapshot("GLOBAL_TAG_PAIR_BASELINE") == {("download", "exec"): 4}
    assert model_state.runtime_model_mapping_snapshot("FILETYPE_BASELINE") == {".bin": {"download": 5}}

def test_stage1778_model_loader_all_corrupt_section_does_not_erase_state() -> None:
    transitions, tags, pairs, filetypes = _configure_model_state()
    transitions[_markov_event_key()]["exec"] = 2
    tags["download"] = 3
    pairs[("download", "exec")] = 4
    filetypes[".bin"]["download"] = 5

    result = model_state.load_runtime_model_baselines(
        current_runtime_model_record({
            "transition_counts": [
                {
                    "type": "markov_event_v2",
                    "context": "global:trusted_benign",
                    "previous_stage": "asset",
                    "source_event": "download",
                    "target": "exec",
                    "count": 2.5,
                }
            ],
            "global_tag_baseline": {"download": 1.25},
            "global_tag_pair_baseline": [
                {"a": "download", "b": "exec", "count": 3.75}
            ],
            "filetype_baseline": {".bin": {"download": 4.5}},
        })
    )

    assert result["loaded"] is False
    assert result["records_loaded"] == 0
    assert {row["reason"] for row in result["model_state_unavailable_reasons"]} == {"fractional_runtime_model_count"}
    assert model_state.runtime_transition_counter_snapshot(
        _markov_event_key()
    ) == {"exec": 2}
    assert model_state.runtime_model_mapping_snapshot(
        "GLOBAL_TAG_BASELINE"
    ) == {"download": 3}
    assert model_state.runtime_model_mapping_snapshot(
        "GLOBAL_TAG_PAIR_BASELINE"
    ) == {("download", "exec"): 4}
    assert model_state.runtime_model_mapping_snapshot(
        "FILETYPE_BASELINE"
    ) == {".bin": {"download": 5}}


def test_stage1778_resource_economics_rejects_hostile_inputs_without_mutation() -> None:
    _HostileNumber.touched = 0
    _HostilePath.touched = 0
    economics = ExtractionEconomics()

    with pytest.raises(ValueError, match="compressed_size_rejected"):
        economics.observe_member(compressed_size=_HostileNumber(), extracted_size=4)
    with pytest.raises(ValueError, match="previous_confidence_rejected"):
        confidence_inertia(_HostileNumber(), 10)
    with pytest.raises(TypeError, match="resource_economics_path_rejected"):
        adaptive_reprice_cost(_HostilePath())

    assert economics.compressed_bytes == 0
    assert economics.extracted_bytes == 0
    assert economics.members == 0
    assert _HostileNumber.touched == 0
    assert _HostilePath.touched == 0


def test_stage1778_quota_rejections_are_transactional_and_no_hook() -> None:
    _HostileNumber.touched = 0
    tracker = ExtractionQuotaTracker(
        ArchiveScanLimits(
            max_depth=2,
            max_members=10,
            max_member_size=1024,
            max_total_extracted_bytes=4096,
            max_total_extracted_files=10,
            max_decompression_ratio=120.0,
        )
    )
    budget = RuntimeBudget(max_descendants=3)

    with pytest.raises(ResourceQuotaExceeded, match="archive_member_count_unsupported"):
        tracker.check_member_count(_HostileNumber())
    with pytest.raises(ResourceQuotaExceeded, match="archive_commit_byte_count_unsupported"):
        tracker.commit_file(_HostileNumber())
    with pytest.raises(ResourceQuotaExceeded, match="runtime_descendant_count_unsupported"):
        budget.reserve_descendant(_HostileNumber())

    assert tracker.members_seen == 0
    assert tracker.files_extracted == 0
    assert tracker.bytes_extracted == 0
    assert budget.descendants == 0
    assert _HostileNumber.touched == 0


def test_stage1778_causal_emit_records_rejected_numeric_inputs_without_hooks() -> None:
    _HostileNumber.touched = 0
    bus = EventBus()

    event = bus.emit(
        "runtime",
        "unit",
        {"stable": True},
        generation=_HostileNumber(),
        parent_seq=_HostileNumber(),
        cost=_HostileNumber(),
    )
    evidence = event.as_dict()["payload"]["input_evidence"]

    assert {item["field_name"] for item in evidence} == {
        "causal_emit_generation",
        "causal_emit_parent_seq",
        "causal_emit_cost",
    }
    assert event.parent_seq is None
    assert event.cost == 0.0
    assert _HostileNumber.touched == 0


def test_stage1778_all_corrupt_causal_checkpoint_preserves_existing_stream() -> None:
    bus = EventBus()
    original = bus.emit("runtime", "unit", {"stable": True})

    bus.restore_checkpoint(
        {
            "events": (
                {"seq": 2.5, "domain": "runtime", "kind": "corrupt"},
                _HostileNumber(),
            )
        }
    )

    assert bus.sequence == original.seq
    assert bus.snapshot() == (original,)
    checkpoint = bus.deterministic_checkpoint()
    assert checkpoint["checkpoint_restore_evidence"]
    assert any(
        item["reason"] == "causal_checkpoint_all_event_rows_rejected"
        for item in checkpoint["checkpoint_restore_evidence"]
    )


def test_stage1778_startup_boundaries_reject_hostile_inputs_without_hooks() -> None:
    _HostilePath.touched = 0
    _HostileArgs.touched = 0

    with pytest.raises(TypeError, match="parent_scan_guard_args_rejected"):
        acquire_parent_scan_guard(
            _HostileArgs(),
            environ_get=lambda _key, default=None: default,
        )
    context = detect_startup_engine_context(_HostilePath())
    with pytest.raises(ValueError, match="scan_dependency_path_rejected"):
        read_file_bytes(_HostilePath())
    with pytest.raises(ValueError, match="scan_dependency_string_content_rejected"):
        scan_strings(_HostilePath(), registry=ScanDependencyRegistry())

    assert context["unknown"] == 1.0
    assert context["input_evidence"][0]["field_name"] == "startup_engine_scan_root"
    assert _HostilePath.touched == 0
    assert _HostileArgs.touched == 0


def test_stage1778_dependency_provider_results_do_not_execute_numeric_hooks() -> None:
    _HostileNumber.touched = 0
    registry = ScanDependencyRegistry()
    registry.update_group(
        "intrastage_provider",
        {
            "intrastage_enabled": lambda: _HostileNumber(),
            "stage_parallel_workers": lambda: _HostileNumber(),
        },
    )

    with pytest.raises(ValueError, match="intrastage_enabled_result_rejected"):
        intrastage_enabled(registry=registry)
    with pytest.raises(ValueError, match="stage_parallel_workers_result_rejected"):
        stage_parallel_workers(registry=registry)

    assert _HostileNumber.touched == 0


def test_stage1778_runtime_flags_and_replay_inputs_reject_hooks_explicitly() -> None:
    _HostileNumber.touched = 0
    owner = RuntimeFlagOwner()

    with pytest.raises(ValueError, match="runtime_flag_name_rejected"):
        owner.get(_HostileNumber())
    with pytest.raises(ValueError, match="runtime_flag_value_rejected"):
        owner.set("unit", value=_HostileNumber())

    graph = build_replay_graph((_HostileNumber(),))
    integrity = validate_replay_integrity((_HostileNumber(),)).as_dict()
    lookup = why_event(_HostileNumber())

    assert graph["node_count"] == 0
    assert graph["input_evidence"][0]["reason"] == "replay_event_rejected"
    assert integrity["ok"] is False
    assert integrity["input_evidence"][0]["reason"] == "replay_event_rejected"
    assert lookup["found"] is False
    assert lookup["input_evidence"][0]["field_name"] == "replay_why_event_sequence"
    assert _HostileNumber.touched == 0


def test_stage1778_explicit_empty_replay_does_not_fall_back_to_global_bus() -> None:
    bus = EventBus()
    bus.emit("runtime", "unit", {"stable": True})

    assert build_replay_graph(())["node_count"] == 0
    assert validate_replay_integrity(()).event_count == 0


def test_stage1778_graph_owner_canonicalizes_before_hash_or_equality_hooks() -> None:
    reset_graph_state()
    _HostileGraphNode.touched = 0
    first = _HostileGraphNode()
    second = _HostileGraphNode()

    update_graph_node_owned(first, risk=2.0)
    add_graph_edge_owned(first, second, edge_type="unit", weight=1.0)

    snapshot = graph_snapshot()
    base = "graph_runtime_text_unavailable:_HostileGraphNode"
    assert tuple(snapshot) == (base, f"{base}#2")
    assert snapshot[base]["edges"] == frozenset((f"{base}#2",))
    assert _HostileGraphNode.touched == 0



def test_stage1969_graph_state_owned_iteration_projection_is_no_hook() -> None:
    reset_graph_state()
    _HostileGraphNode.touched = 0
    first = _HostileGraphNode()
    second = _HostileGraphNode()
    third = _HostileGraphNode()

    update_graph_node_owned(first, risk=1.0, tags=(second,))
    add_graph_edge_owned(first, second, edge_type="unit", weight=2.0)
    add_graph_edge_owned(first, third, edge_type="unit", weight=3.0)
    decay_graph_weights_owned(decay=0.5, min_weight=0.1)

    rows = graph_node_snapshots()
    snapshot = graph_snapshot()
    prune_graph_owned(max_nodes=10, max_edges_per_node=1)
    pruned_snapshot = graph_snapshot()

    base = "graph_runtime_text_unavailable:_HostileGraphNode"
    assert tuple(snapshot) == (base, base + "#2", base + "#3")
    assert tuple(row[0] for row in rows) == (base, base + "#2", base + "#3")
    assert pruned_snapshot[base]["edges"] == frozenset((base + "#3",))
    assert _HostileGraphNode.touched == 0

def test_stage1778_cluster_snapshot_records_vector_and_rank_rejections() -> None:
    _HostileNumber.touched = 0
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    state.cluster_signatures["corrupt"] = [_HostileNumber(), float("nan"), 2.0]
    state.cluster_metadata["corrupt"] = {
        "confidence": _HostileNumber(),
        "malicious_ratio": "not-a-number",
        "samples": 2.5,
        "last_updated": float("inf"),
        "centroid_vector": [_HostileNumber(), 3.0],
    }

    snapshot = runtime_cluster_state_to_json()
    metadata = snapshot["microclusters"]["corrupt"]

    assert "cluster_signatures" not in snapshot
    assert metadata["confidence_unavailable_reason"] == "unsafe_cluster_metadata_value_rejected"
    assert metadata["malicious_ratio_unavailable_reason"] == "unsafe_malicious_ratio_rejected"
    assert metadata["samples_unavailable_reason"] == "unsafe_cluster_samples_rejected"
    assert metadata["last_updated_unavailable_reason"] == "nonfinite_cluster_numeric_value"
    assert metadata["centroid_vector"] == [0.0, 3.0]
    assert metadata["centroid_vector_unavailable_reasons"][0]["index"] == 0
    assert _HostileNumber.touched == 0


def test_stage1778_cluster_state_binding_rejects_subclasses() -> None:
    class _CallerOwnedClusterState(RuntimeClusterState):
        pass

    with pytest.raises(TypeError, match="runtime cluster state must be RuntimeClusterState"):
        configure_runtime_cluster_state(_CallerOwnedClusterState())


def test_stage1778_causal_budget_rejects_inputs_before_admission_mutation() -> None:
    _HostileNumber.touched = 0
    budget = WorkloadEventBudget()

    allowed, reason = budget.allow("unit", _HostileNumber())

    assert allowed is False
    assert reason == "event_budget_input_rejected"
    assert budget.emitted == 0
    assert budget.cost == 0.0
    assert budget.per_key == {}
    assert budget.suppressed == 1
    assert _HostileNumber.touched == 0


def test_stage1778_causal_query_limits_reject_hooks_before_locking() -> None:
    _HostileNumber.touched = 0
    bus = EventBus()

    with pytest.raises(ValueError, match="causal since sequence rejected"):
        bus.since(_HostileNumber())
    with pytest.raises(ValueError, match="causal trace sequence rejected"):
        bus.trace(_HostileNumber())
    with pytest.raises(ValueError, match="compressed replay payload-key limit rejected"):
        bus.compressed_replay(max_payload_keys=_HostileNumber())
    with pytest.raises(ValueError, match="compressed causal trace limit rejected"):
        bus.compressed_causal_trace(max_events=_HostileNumber())
    with pytest.raises(ValueError, match="causal trace visualization limit rejected"):
        bus.causal_trace_visualization(max_events=_HostileNumber())

    assert _HostileNumber.touched == 0


def test_stage1778_governance_read_model_rejects_non_owner_before_attributes() -> None:
    class _HostileRoot:
        touched = 0

        @property
        def bus(self):  # pragma: no cover - regression asserts no access
            type(self).touched += 1
            raise AssertionError("do not traverse caller-owned root")

    with pytest.raises(TypeError, match="governance read model root must be RuntimeRoot"):
        build_governance_read_model(_HostileRoot())

    assert _HostileRoot.touched == 0


def test_stage1778_graph_prune_releases_external_identity_references() -> None:
    reset_graph_state()
    first = _HostileGraphNode()
    second = _HostileGraphNode()
    first_identity = id(first)
    second_identity = id(second)
    update_graph_node_owned(first, risk=1.0)
    update_graph_node_owned(second, risk=2.0)

    prune_graph_owned(max_nodes=1, max_edges_per_node=10)

    owner = graph_owner()
    assert first_identity not in owner._external_node_refs
    assert first_identity not in owner._external_node_keys
    assert owner._external_node_refs[second_identity] is second


def test_stage1778_runtime_owner_rejects_hostile_refresh_transactionally() -> None:
    _HostileMapping.touched = 0
    _HostileNumber.touched = 0
    owner = RuntimeStateOwner()
    owner.set("stable", {"value": 1})

    with pytest.raises(TypeError, match="runtime owner refresh state rejected"):
        owner.refresh(_HostileMapping({"replacement": 2}))
    with pytest.raises(ValueError, match="runtime_owner_set_key rejected"):
        owner.set(_HostileNumber(), 3)

    assert owner.snapshot()["stable"]["value"] == 1
    assert _HostileMapping.touched == 0
    assert _HostileNumber.touched == 0


def test_stage1778_deterministic_inventory_rejects_hostile_paths_without_hooks() -> None:
    _HostilePath.touched = 0

    with pytest.raises(TypeError, match="deterministic inventory root rejected"):
        deterministic_path_inventory(_HostilePath())
    with pytest.raises(TypeError, match="deterministic inventory root rejected"):
        deterministic_scan_path_inventory(_HostilePath())

    assert _HostilePath.touched == 0


def test_stage1778_provenance_capacity_rejects_hostile_numeric_without_hooks() -> None:
    _HostileNumber.touched = 0

    with pytest.raises(ValueError, match="provenance ledger max events rejected"):
        ProvenanceLedger(max_events=_HostileNumber())

    assert _HostileNumber.touched == 0


def test_stage1778_yara_snapshot_rejects_nonfinite_runtime_numbers() -> None:
    snapshot = YaraRulesSnapshot(
        rules={"score": float("nan")},
        loaded_count=-1,
    )

    assert snapshot.loaded_count == 0
    assert snapshot.rules["score"]["unavailable_reason"] == (
        "yara_snapshot_nonfinite_number_rejected"
    )


def test_stage1778_failure_owner_capacities_reject_hostile_numbers() -> None:
    _HostileNumber.touched = 0

    with pytest.raises(ValueError, match="internal trail limit rejected"):
        FailureRecorderInternalTrail(_HostileNumber())
    with pytest.raises(ValueError, match="store max records rejected"):
        FailureRecordStore(max_records=_HostileNumber())
    with pytest.raises(ValueError, match="failure record scalar field rejected"):
        FailureRecord("runtime", "unit", "Failure", "bad", count=_HostileNumber())

    assert _HostileNumber.touched == 0


def test_stage1778_runtime_budget_malformed_env_fails_closed() -> None:
    name = "UMIGE_MAX_DESCENDANTS"
    previous = os.environ.get(name)
    os.environ[name] = "2.5"
    try:
        with pytest.raises(
            ResourceQuotaExceeded,
            match="umige_max_descendants_unsupported",
        ):
            RuntimeBudget.from_env()
    finally:
        if previous is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous


def test_stage1778_telemetry_constructor_rejects_hostile_policy_inputs() -> None:
    _HostileNumber.touched = 0

    with pytest.raises(ValueError, match="runtime telemetry configuration rejected"):
        RuntimeTelemetry(max_events=_HostileNumber())
    with pytest.raises(TypeError, match="runtime telemetry counters owner rejected"):
        RuntimeTelemetry(counters=_HostileMapping())

    assert _HostileNumber.touched == 0
    assert _HostileMapping.touched == 0


def test_stage1778_architecture_limit_rejection_is_visible_without_hooks() -> None:
    _HostileNumber.touched = 0

    visual = causal_architecture_visualization(
        (),
        {},
        max_events=_HostileNumber(),
    )

    assert visual["nodes"][0]["kind"] == "unsupported_event"
    assert visual["nodes"][0]["event_unavailable_reason"] == (
        "unsafe_architecture_max_events_rejected"
    )
    assert _HostileNumber.touched == 0


def test_stage1778_cleanup_snapshot_rejects_hostile_process_ids() -> None:
    _HostileNumber.touched = 0

    with pytest.raises(ValueError, match="runtime cleanup process ids rejected"):
        RuntimeCleanupSnapshot((), (_HostileNumber(),), (), ())

    assert _HostileNumber.touched == 0


def test_stage1778_detector_strict_configuration_rejects_before_mutation() -> None:
    _HostileNumber.touched = 0
    owner = DetectorStateOwner()

    with pytest.raises(ValueError, match="detector state strict mode rejected"):
        owner.configure(strict=_HostileNumber())

    assert owner.strict() is False
    assert _HostileNumber.touched == 0


def test_stage1778_fault_domain_tag_rejects_hostile_text_without_hooks() -> None:
    _HostileNumber.touched = 0

    assert failure_tag(_HostileNumber()) == "failure_domain_input_rejected"
    assert _HostileNumber.touched == 0


def test_stage1778_causal_snapshot_records_invalid_exact_integer_inputs() -> None:
    snapshot = build_causal_snapshot(
        events=(
            {
                "seq": "fractional",
                "domain": "runtime",
                "kind": "unit",
                "event_key": "unit",
            },
        ),
        generation="invalid",
    ).as_dict()

    assert snapshot["generation"] == 0
    assert snapshot["input_evidence"][0]["field_name"] == (
        "causal_snapshot_generation"
    )
    assert snapshot["events"][0]["seq"] == 0
    assert snapshot["events"][0]["input_evidence"][0]["field_name"] == (
        "causal_snapshot_event_seq"
    )


def test_stage1778_emergent_invalid_exact_numeric_is_not_clean_default() -> None:
    result = immutable_orchestration_invariants(
        (
            {
                "seq": "invalid",
                "parent_seq": "invalid",
                "causal_depth": "invalid",
                "domain": "governance",
            },
        )
    )

    assert result["ok"] is False
    assert result["input_rejected"] is True


@pytest.mark.parametrize(
    ("base", "args", "message"),
    (
        (WorkComplexitySignal, ("archive",), "work complexity signal owner rejected"),
        (ArchiveComplexityScore, (), "archive complexity score owner rejected"),
        (
            CausalEvent,
            (1, "lineage", "runtime", "event"),
            "causal event owner rejected",
        ),
        (
            ReplayTombstone,
            (1, "lineage", "runtime", "event", "reason"),
            "replay tombstone owner rejected",
        ),
        (WorkloadEventBudget, (), "workload event budget owner rejected"),
        (
            CausalReplaySnapshot,
            (1, 0, 0, "digest"),
            "causal replay snapshot owner rejected",
        ),
        (
            FailureRecord,
            ("runtime", "unit", "Failure", "bad"),
            "failure record owner rejected",
        ),
        (CircuitBreakerState, (), "circuit breaker state owner rejected"),
        (
            RuntimeInvariantReport,
            (True,),
            "runtime invariant report owner rejected",
        ),
        (
            EventContract,
            ("runtime", "event", "runtime"),
            "event contract owner rejected",
        ),
        (GovernancePlane, ("runtime",), "governance plane owner rejected"),
        (
            ReplayIntegrityReport,
            (True, 0, 0, 0, 0, 0),
            "replay integrity report owner rejected",
        ),
        (WorkloadDebt, ("workload",), "workload debt owner rejected"),
        (
            StabilizationDecision,
            ("observe", "stable"),
            "stabilization decision owner rejected",
        ),
        (
            ArbitrationResult,
            ("observe", "stable"),
            "arbitration result owner rejected",
        ),
    ),
)
def test_stage1778_public_runtime_records_reject_subclass_owners(
    base, args, message
) -> None:
    subclass = type(f"Hostile{base.__name__}", (base,), {})

    with pytest.raises(TypeError, match=message):
        subclass(*args)


def test_stage1778_causal_snapshot_rejects_hostile_evidence_sequence_no_hook() -> None:
    _HostileSequence.touched = 0

    snapshot = CausalReplaySnapshot(
        0,
        0,
        0,
        "digest",
        input_evidence=_HostileSequence(),
    ).as_dict()

    assert snapshot["input_evidence"][0]["field_name"] == (
        "causal_snapshot_input_evidence"
    )
    assert _HostileSequence.touched == 0


def test_stage1778_runtime_root_replay_snapshot_rejects_corrupt_bus_no_hook() -> None:
    _HostileBus.touched = 0
    root = RuntimeRoot()
    root.bus = _HostileBus()

    with pytest.raises(TypeError, match="runtime root event bus owner rejected"):
        root.replay_snapshot()

    assert _HostileBus.touched == 0


def test_stage1778_extraction_quota_tracker_rejects_subclass_owner() -> None:
    subclass = type(
        "HostileExtractionQuotaTracker",
        (ExtractionQuotaTracker,),
        {},
    )

    with pytest.raises(
        ResourceQuotaExceeded,
        match="archive_quota_tracker_owner_unsupported",
    ):
        subclass(ArchiveScanLimits())


def test_stage1778_readonly_generation_accepts_exact_text_without_hooks() -> None:
    _HostileNumber.touched = 0

    assert ReadonlyRuntimeView({}, generation="2").generation == 2
    assert ReadonlyRuntimeView({}, generation=_HostileNumber()).generation == 0
    assert _HostileNumber.touched == 0


def test_stage1778_causal_text_rejects_numeric_subclasses_without_repr() -> None:
    _HostileNumber.touched = 0

    assert causal_text(_HostileNumber()).startswith("causal_text_unavailable:")
    assert _HostileNumber.touched == 0


def test_stage1778_entropy_governance_rejects_hostile_root_without_fspath() -> None:
    _HostilePath.touched = 0

    with pytest.raises(TypeError, match="entropy governance root rejected"):
        audit_entropy(_HostilePath())

    assert _HostilePath.touched == 0


def test_stage1778_runtime_architecture_guards() -> None:
    runtime_root = Path(__file__).resolve().parents[1] / "runtime"
    oversized: list[str] = []
    local_imports: list[str] = []
    dynamic_imports: list[str] = []
    broad_exceptions: list[str] = []
    unguarded_post_init: list[str] = []

    for source_path in tuple(path for path in python_files_under("Virus_Scan/runtime") if path.parent == runtime_root):
        tree = parse_python_file(source_path)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                post_init = next(
                    (
                        child
                        for child in node.body
                        if isinstance(child, ast.FunctionDef)
                        and child.name == "__post_init__"
                    ),
                    None,
                )
                if post_init is not None:
                    has_owner_check = any(
                        isinstance(child, ast.Call)
                        and isinstance(child.func, ast.Name)
                        and child.func.id == "type"
                        and len(child.args) == 1
                        and isinstance(child.args[0], ast.Name)
                        and child.args[0].id == "self"
                        for child in ast.walk(post_init)
                    )
                    if not has_owner_check:
                        unguarded_post_init.append(
                            f"{source_path.name}:{node.lineno}:{node.name}"
                        )
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                span = (node.end_lineno or node.lineno) - node.lineno + 1
                if span > 100:
                    oversized.append(f"{source_path.name}:{node.lineno}:{span}")
                for child in ast.walk(node):
                    if isinstance(child, (ast.Import, ast.ImportFrom)):
                        local_imports.append(
                            f"{source_path.name}:{child.lineno}"
                        )
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                    dynamic_imports.append(f"{source_path.name}:{node.lineno}")
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "import_module"
                ):
                    dynamic_imports.append(f"{source_path.name}:{node.lineno}")
            if (
                isinstance(node, ast.ExceptHandler)
                and isinstance(node.type, ast.Name)
                and node.type.id == "Exception"
            ):
                broad_exceptions.append(f"{source_path.name}:{node.lineno}")

    assert oversized == []
    assert local_imports == []
    assert dynamic_imports == []
    assert broad_exceptions == []
    assert unguarded_post_init == []
