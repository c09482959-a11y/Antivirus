
"""Stage1966 runtime detector/determinism no-hook closure regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import os
from pathlib import Path

import pytest

from Virus_Scan.runtime.detector_state import DetectorStateOwner
from Virus_Scan.runtime.determinism import (
    canonicalize_result_mapping,
    deterministic_json_dumps,
    deterministic_queue_order,
    validate_deterministic_result_records,
)
from Virus_Scan.runtime.emergent_simulation import simulate_emergent_behaviors
from Virus_Scan.runtime.engine_hint_runtime import _media_magic_result
from Virus_Scan.runtime.environment import RuntimeEnvironmentOwner
from Virus_Scan.runtime.event_contracts import (
    EventContract,
    event_contract_snapshot,
    get_event_contract,
)
from Virus_Scan.runtime.fault_domains import failure_tag
from Virus_Scan.runtime.governance_inputs import (
    runtime_bool,
    runtime_float,
    runtime_int,
    runtime_mapping,
    runtime_object_state,
    runtime_sequence,
    runtime_text,
)
from Virus_Scan.runtime.governance_invariants import (
    CircuitBreakerState,
    RuntimeInvariantReport,
    assert_acyclic_edges,
    evaluate_runtime_invariants,
)


class Stage1966HostileText:
    touched = 0

    def __str__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("text str hook executed")

    def __repr__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("text repr hook executed")

    def __format__(self, spec):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("text format hook executed")

    def __bool__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("text bool hook executed")


def test_stage1966_runtime_source_closes_detector_and_determinism_rows() -> None:
    detector_source = read_python_file(Path("Virus_Scan/runtime/detector_state.py"))
    determinism_source = read_python_file(Path("Virus_Scan/runtime/determinism.py"))

    forbidden = {
        "detector_state.py": (
            "error = safe_exception_message(exc)",
            "from Virus_Scan.runtime.structured_failures import safe_exception_message",
        ),
        "determinism.py": (
            'return f"~{reason}:{no_hook_type_name(value)}"',
            'return no_hook_failure(f"non_materializable_{context}_mapping", value)',
            'key_text, key_reason = no_hook_json_key(key, index, prefix=f"{context}_key")',
            'key_text = f"{key_text}#{index}"',
            "for key, item in sorted(dict.items(safe), key=lambda row: row[0].casefold())",
            'raise ValueError(f"duplicate deterministic result record for {normalized}: {previous!r} and {key_text!r}")',
            'raise TypeError(f"result record for {key_text!r} must be a mapping")',
            'raise ValueError(f"result record for {key_text!r} is missing verdict")',
        ),
    }

    assert {
        "detector_state.py": [
            pattern for pattern in forbidden["detector_state.py"] if pattern in detector_source
        ],
        "determinism.py": [
            pattern for pattern in forbidden["determinism.py"] if pattern in determinism_source
        ],
    } == {"detector_state.py": [], "determinism.py": []}


def test_stage1966_runtime_source_closes_emergent_engine_contract_governance_rows() -> None:
    sources = {
        "emergent_simulation.py": Path(
            "Virus_Scan/runtime/emergent_simulation.py"
        ).read_text(),
        "engine_hint_runtime.py": Path(
            "Virus_Scan/runtime/engine_hint_runtime.py"
        ).read_text(),
        "environment.py": read_python_file(Path("Virus_Scan/runtime/environment.py")),
        "event_contracts.py": Path(
            "Virus_Scan/runtime/event_contracts.py"
        ).read_text(),
        "fault_domains.py": read_python_file(Path("Virus_Scan/runtime/fault_domains.py")),
        "governance_inputs.py": Path(
            "Virus_Scan/runtime/governance_inputs.py"
        ).read_text(),
        "governance_invariants.py": Path(
            "Virus_Scan/runtime/governance_invariants.py"
        ).read_text(),
    }
    forbidden = {
        "emergent_simulation.py": (
            'field_name=f"{field_name}_{index}"',
            "for key, item in dict.items(value):",
            "key: value for key, value in dict.items(materialized)",
            'field_name=f"emergent_event_{field_name}"',
            'normalized[f"{field_name}_unavailable_reason"] = issues[0]["reason"]',
            'materialized = materialize_json_no_hook(value, context=f"emergent_{field}", max_depth=8)',
            'dict.values(budgets)',
        ),
        "engine_hint_runtime.py": (
            "return False",
            'f"startup_engine_scan_unavailable:{type(exc).__name__}"',
            'field_name=f"startup_engine_context_{key}"',
        ),
        "environment.py": ("os.environ.values()",),
        "event_contracts.py": (
            'field_name=f"event_contract_{field_name}"',
            'raise ValueError(f"event contract {field_name} rejected")',
            'field_name=f"event_contract_required_field_{index}"',
            'return f"{self.domain}:{self.kind}"',
            'key = f"{domain_text}:{kind_text}"',
            'raise KeyError(f"unregistered event contract: {key}")',
            "sorted(_EVENT_CONTRACTS.items())",
        ),
        "fault_domains.py": ('return f"failure_domain_{normalized or \'runtime\'}"',),
        "governance_inputs.py": (
            'f"{field_name}_mapping_rejected"',
            'f"{field_name}_sequence_rejected"',
            'f"{field_name}_object_rejected"',
            'f"{field_name}_missing"',
            'f"{field_name}_rejected"',
            'f"{field_name}_blank"',
            'f"{field_name}_non_finite"',
        ),
        "governance_invariants.py": (
            'field_name=f"circuit_breaker_reason_{index}"',
            'field_name=f"circuit_breaker_{field_name}"',
            'field_name=f"runtime_invariant_violation_{index}"',
            'row, field_name=f"governance_lineage_edge_{index}"',
            '"field_name": f"governance_lineage_edge_{index}"',
            'field_name=f"governance_lineage_parent_{index}"',
            'field_name=f"governance_lineage_child_{index}"',
            'field_name=f"runtime_invariant_{field_name}"',
            'field_name=f"governance_limit_{field_name}"',
            'f"replay_depth_exceeded:{metrics[\'replay_depth\']}>{limit_values[\'max_replay_depth\']}"',
            'f"lineage_fanout_exceeded:{metrics[\'lineage_fanout\']}>{limit_values[\'max_lineage_fanout\']}"',
            'f"descendant_budget_exceeded:{metrics[\'descendants\']}>{limit_values[\'max_descendants_per_root\']}"',
            'f"telemetry_budget_exceeded:{metrics[\'telemetry_events\']}>{limit_values[\'max_telemetry_events_per_workload\']}"',
            'f"replay_node_budget_exceeded:{metrics[\'replay_nodes\']}>{limit_values[\'max_replay_nodes_per_workload\']}"',
            'f"scheduler_debt_exceeded:{metrics[\'scheduler_debt\']}>{limit_values[\'max_scheduler_debt\']}"',
        ),
    }

    assert {
        name: [pattern for pattern in patterns if pattern in sources[name]]
        for name, patterns in forbidden.items()
    } == {name: [] for name in forbidden}


def test_stage1966_detector_exception_args_record_evidence_without_hooks() -> None:
    Stage1966HostileText.touched = 0
    hostile = Stage1966HostileText()
    owner = DetectorStateOwner()

    entry = owner.record(hostile, RuntimeError(hostile), {"path": hostile})

    assert entry["detector"] == "detector_input_rejected"
    assert entry["error"] == "RuntimeError"
    evidence = entry["input_evidence"]
    assert evidence["detector_reason"] == "detector_name_rejected"
    assert evidence["error_reason"] == "detector_error_text_rejected"
    assert evidence["error_type"] == "RuntimeError"
    snapshot = owner.snapshot()
    assert snapshot[0]["context"]["path"]["unavailable_reason"] == "non_materializable_runtime_value"
    assert Stage1966HostileText.touched == 0


def test_stage1966_governance_input_reason_builders_reject_field_hooks() -> None:
    Stage1966HostileText.touched = 0
    hostile = Stage1966HostileText()

    _mapping, mapping_issues = runtime_mapping(hostile, field_name=hostile)
    _sequence, sequence_issues = runtime_sequence(hostile, field_name=hostile)
    _state, object_issues = runtime_object_state(object(), field_name=hostile)
    _text, text_issues = runtime_text(None, field_name=hostile, default="fallback")
    _integer, int_issues = runtime_int(hostile, field_name=hostile)
    _metric, float_issues = runtime_float(hostile, field_name=hostile)
    _flag, bool_issues = runtime_bool(hostile, field_name=hostile)

    issue_sets = (
        mapping_issues,
        sequence_issues,
        object_issues,
        text_issues,
        int_issues,
        float_issues,
        bool_issues,
    )
    assert [issues[0]["field_name"] for issues in issue_sets] == ["runtime_input"] * 7
    assert [issues[0]["reason"].startswith("runtime_input_") for issues in issue_sets] == [True] * 7
    assert Stage1966HostileText.touched == 0


def test_stage1966_runtime_boundary_cluster_rejects_hooks_and_records_evidence(tmp_path: Path) -> None:
    Stage1966HostileText.touched = 0
    hostile = Stage1966HostileText()

    report = simulate_emergent_behaviors(
        [{"seq": 1, "domain": "runtime", "kind": "event"}],
        budgets={"worker": {"suppressed": hostile}},
        topology={"pressure": hostile},
        convergence={"violated": hostile},
    )
    matched, evidence = _media_magic_result(tmp_path / "missing.bin")
    saved = os.environ.get("UMIGE_STAGE1966_NEEDLE")
    os.environ["UMIGE_STAGE1966_NEEDLE"] = "stage1966_visible_value"
    try:
        owner = RuntimeEnvironmentOwner()
        contains_value = owner.contains_text("stage1966_visible_value")
        contains_hostile = owner.contains_text(hostile)
    finally:
        if saved is None:
            os.environ.pop("UMIGE_STAGE1966_NEEDLE", None)
        else:
            os.environ["UMIGE_STAGE1966_NEEDLE"] = saved

    with pytest.raises(KeyError, match="input_rejected"):
        get_event_contract(hostile, "event")
    with pytest.raises(ValueError, match="event contract required field rejected"):
        EventContract("runtime", "unit", "runtime", required_fields=(hostile,))

    assert report.as_dict()["graceful_degradation"]["input_rejected"] is True
    assert matched is False
    assert evidence is not None
    assert evidence["reason"] == "startup_engine_media_magic_unavailable:FileNotFoundError"
    assert contains_value is True
    assert contains_hostile is False
    assert EventContract("runtime", "unit", "runtime").key == "runtime:unit"
    assert list(event_contract_snapshot()) == sorted(event_contract_snapshot())
    assert failure_tag(hostile) == "failure_domain_input_rejected"
    assert Stage1966HostileText.touched == 0


def test_stage1966_governance_invariants_reject_hooks_without_formatting() -> None:
    Stage1966HostileText.touched = 0
    hostile = Stage1966HostileText()

    cb = CircuitBreakerState(replay_frozen=hostile, reasons=(hostile,))
    report = RuntimeInvariantReport(True, violations=(hostile,), checked_at=hostile)
    lineage = assert_acyclic_edges(((hostile, "child"), ("child", "root", "extra")))
    evaluated = evaluate_runtime_invariants(
        replay_nodes=hostile,
        replay_depth=99,
        lineage_fanout=999,
        descendants=9999,
        telemetry_events=9999,
        scheduler_debt=999999.0,
    )

    assert cb.replay_frozen is True
    assert "runtime_input_rejected" in cb.reasons
    assert report.ok is False
    assert "runtime_input_rejected" in report.violations
    assert "runtime_input_rejected:lineage_edges" in lineage
    assert evaluated.ok is False
    assert "runtime_input_rejected" in evaluated.violations
    assert any(item.startswith("replay_depth_exceeded:99>") for item in evaluated.violations)
    assert Stage1966HostileText.touched == 0


def test_stage1966_determinism_key_and_error_paths_reject_hooks() -> None:
    Stage1966HostileText.touched = 0
    hostile = Stage1966HostileText()

    ordered = deterministic_queue_order([hostile, "safe.bin"])
    canonical = canonicalize_result_mapping(
        {
            hostile: {"verdict": "Low"},
            "safe.bin": {"verdict": "Clean", "pid": 10},
        }
    )
    dumped = deterministic_json_dumps({"unsafe": {hostile: hostile}})

    assert ordered[0] == "safe.bin"
    assert type(ordered[1]) is Stage1966HostileText
    assert any(key.startswith("runtime_result_key_") for key in canonical)
    assert canonical["safe.bin"] == {"verdict": "Clean"}
    assert "runtime_determinism_key_0" in dumped
    with pytest.raises(ValueError, match="duplicate deterministic result record"):
        validate_deterministic_result_records(
            {
                "A/file.bin": {"verdict": "Clean"},
                "a\\file.bin": {"verdict": "Clean"},
            }
        )
    with pytest.raises(TypeError, match="must be a mapping"):
        validate_deterministic_result_records({"sample.bin": [hostile]})
    with pytest.raises(ValueError, match="missing verdict"):
        validate_deterministic_result_records({"sample.bin": {"tags": [hostile]}})
    assert Stage1966HostileText.touched == 0
