from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from Virus_Scan.runtime import scan_dependencies as deps
from Virus_Scan.runtime import scan_run_guard
from Virus_Scan.runtime import structured_failures
from Virus_Scan.runtime.stabilization_arbitration import ArbitrationResult, arbitrate_stabilization
from Virus_Scan.runtime.stability_policy import StabilizationDecision, decide_stabilization
from Virus_Scan.runtime.scanner_governance import ScannerContext, ScannerContractViolation, run_collector
from Virus_Scan.runtime.scheduler_runtime_state import SchedulerRuntimeState
from Virus_Scan.runtime.state_domains import RuntimeDomain, RuntimeDomainRegistry
from Virus_Scan.runtime.telemetry import RuntimeTelemetry
from Virus_Scan.runtime.telemetry_governance import WorkloadTelemetryBudget
from Virus_Scan.runtime.temporal_state import invalidate_temporal_cache, temporal_state_node_key
from Virus_Scan.runtime.topology_stabilization import TopologyStabilizationReport, analyze_topology_pressure
from Virus_Scan.runtime.transactional_state import RuntimeTransaction, TransactionalRuntimeJournal
from Virus_Scan.runtime.yara_rules_state import YaraRulesSnapshot


class HostileText:
    touched = 0

    def __str__(self) -> str:  # pragma: no cover - must never run
        type(self).touched += 1
        raise AssertionError("hostile str hook executed")

    def __repr__(self) -> str:  # pragma: no cover - must never run
        type(self).touched += 1
        raise AssertionError("hostile repr hook executed")

    def __format__(self, spec: str) -> str:  # pragma: no cover - must never run
        type(self).touched += 1
        raise AssertionError("hostile format hook executed")

    def __bool__(self) -> bool:  # pragma: no cover - must never run
        type(self).touched += 1
        raise AssertionError("hostile bool hook executed")


class HostileArgs:
    touched = 0

    @property
    def __dict__(self) -> dict[str, object]:  # pragma: no cover - must never run
        type(self).touched += 1
        raise AssertionError("hostile args dict hook executed")


def test_stage1979_runtime_dependency_and_guard_reject_hostile_fields_without_hooks() -> None:
    HostileText.touched = 0
    HostileArgs.touched = 0
    hostile = HostileText()
    registry = deps.ScanDependencyRegistry()

    with pytest.raises(ValueError, match="scan_dependency_input_missing"):
        deps._dependency_text(None, hostile)
    with pytest.raises(ValueError, match="scan_dependency_provider_name_rejected"):
        registry.get_single(hostile)
    with pytest.raises(TypeError, match="scan_strings_provider provider must be callable"):
        registry.set_single("scan_strings_provider", object())

    with pytest.raises(ValueError, match="parent_scan_guard_input_missing"):
        scan_run_guard._guard_text(None, hostile)
    with pytest.raises(TypeError, match="parent_scan_guard_args_rejected"):
        scan_run_guard._guard_args_state(HostileArgs())
    assert scan_run_guard._guard_args_state(SimpleNamespace(dir="target", scan_log_root="Scan Logs")) == {
        "dir": "target",
        "scan_log_root": "Scan Logs",
    }

    assert HostileText.touched == 0
    assert HostileArgs.touched == 0


def test_stage1979_parent_guard_failure_paths_record_evidence(tmp_path: Path) -> None:
    structured_failures.clear_failure_records()
    original_kill = scan_run_guard.os.kill
    scan_run_guard.os.kill = lambda _pid, _sig: (_ for _ in ()).throw(OSError("probe failed"))
    try:
        assert scan_run_guard._pid_alive(999999) is True
        records = structured_failures.failure_snapshot()["records"]
        assert records[0]["where"] == "parent_scan_guard_pid_probe_failed"
    finally:
        scan_run_guard.os.kill = original_kill

    args = SimpleNamespace(
        dir=str(tmp_path / "game"),
        scan_log_root=str(tmp_path / "Scan Logs"),
    )
    Path(args.dir).mkdir()
    lock = scan_run_guard.acquire_parent_scan_guard(args, environ_get=lambda _key, default=None: default)
    assert lock is not None
    lock.write_text("{", encoding="utf-8")
    try:
        with pytest.raises(RuntimeError, match="parent_scan_guard_release_lock_unreadable"):
            scan_run_guard.release_parent_scan_guard()
    finally:
        lock.unlink(missing_ok=True)


def test_stage1979_structured_failure_routes_reject_hostile_values_without_hooks() -> None:
    HostileText.touched = 0
    hostile = HostileText()
    logs: list[str] = []

    record = structured_failures.record_failure(
        hostile,
        hostile,
        RuntimeError(hostile),
        logger=logs.append,
        context={hostile: hostile},
    )
    tag = structured_failures.record_suppressed_failure(hostile, RuntimeError(hostile), domain=hostile)

    assert record.domain == "runtime"
    assert record.where == "unknown"
    assert record.message == "RuntimeError"
    assert logs and logs[0].startswith("[runtime] unknown: RuntimeError: RuntimeError")
    assert tag == "failure_runtime_unknown"
    assert HostileText.touched == 0


def test_stage1979_telemetry_and_stabilization_reject_hostile_inputs_without_hooks() -> None:
    HostileText.touched = 0
    HostileArgs.touched = 0
    hostile = HostileText()
    hostile_event = HostileArgs()

    telemetry = RuntimeTelemetry()
    telemetry.event(hostile, hostile, important=hostile, detail=hostile)
    telemetry.queue_metric(hostile, latency=1.5)
    telemetry.quota_activation(hostile)
    telemetry.failure_domain(hostile, where=hostile)
    snapshot = telemetry.snapshot()

    decision = StabilizationDecision(
        hostile,
        hostile,
        freeze_replay=hostile,
        details={hostile: hostile},
    )
    policy = decide_stabilization(
        budgets={hostile: {"suppressed": hostile, "cost": hostile}},
        topology={"event_count": hostile, "pressure": hostile},
        lineage_pressure={"action": hostile, "pressure": hostile},
    )
    arbitration = arbitrate_stabilization(
        events=[hostile],
        budgets={hostile: {"suppressed": hostile, "cost": hostile}},
    )
    topology = TopologyStabilizationReport(hostile, hostile, anomalies=(hostile,), actions=(hostile,), metrics={hostile: hostile})
    analyzed = analyze_topology_pressure([hostile_event])

    assert snapshot["events"][0]["domain"] == "runtime_input_rejected"
    assert decision.action == "degrade"
    assert policy.action == "degrade"
    assert arbitration.action == "degrade"
    assert topology.ok is False
    assert analyzed.ok is False
    assert HostileText.touched == 0
    assert HostileArgs.touched == 0


def test_stage1979_remaining_runtime_routes_close_no_hook_rows() -> None:
    HostileText.touched = 0
    hostile = HostileText()

    assert temporal_state_node_key(hostile).startswith("<HostileText")
    invalidate_temporal_cache(hostile)

    budget = WorkloadTelemetryBudget(max_replay_traces=4, max_governance_emissions=4)
    replay_rejection = budget.record_replay_trace(hostile, payload={hostile: hostile})
    governance_rejection = budget.record_governance(hostile, payload={hostile: hostile})
    assert replay_rejection is not None and replay_rejection["runtime_input_rejected"] is True
    assert governance_rejection is not None and governance_rejection["runtime_input_rejected"] is True

    domain = RuntimeDomain("runtime", max_mutations=1)
    domain.set("first", 1)
    with pytest.raises(RuntimeError, match="mutation budget exceeded for domain runtime"):
        domain.set("second", 2)
    with pytest.raises(KeyError, match="unregistered runtime ownership domain"):
        RuntimeDomainRegistry().domain(hostile)

    with pytest.raises(PermissionError, match="transaction owner 'runtime' cannot contain transition for 'other'"):
        RuntimeTransaction.build(
            owner="runtime",
            transitions=({"owner": "other", "action": "set", "key": "x", "value": 1},),
        )
    journal = TransactionalRuntimeJournal(owner="runtime")
    foreign_tx = RuntimeTransaction.build(
        owner="other",
        transitions=({"owner": "other", "action": "set", "key": "x", "value": 1},),
    )
    with pytest.raises(PermissionError, match="journal owner mismatch"):
        journal.apply(foreign_tx)

    snapshot = YaraRulesSnapshot(rules={hostile: {hostile: hostile}, "safe": "value"})
    assert "safe" in snapshot.rules

    ctx = ScannerContext()
    with pytest.raises(ScannerContractViolation, match="collector contract violation at collector: TypeError"):
        run_collector(ctx, hostile, lambda: (_ for _ in ()).throw(TypeError(hostile)))

    scheduler_state = SchedulerRuntimeState()
    scheduler_state.configure_raw_stage_cache(max_entries=1)
    scheduler_state.raw_stage_cache_put("first", {"value": 1})
    scheduler_state.raw_stage_cache_put("second", {"value": 2})
    assert list(scheduler_state.raw_stage_cache_snapshot()) == ["second"]
    assert scheduler_state.raw_stage_cache_get(hostile) is None

    assert HostileText.touched == 0


def test_stage1979_runtime_no_hook_source_guard_closes_current_rows() -> None:
    repaired_sources = [
        Path("Virus_Scan/runtime/scan_dependencies.py"),
        Path("Virus_Scan/runtime/scan_run_guard.py"),
        Path("Virus_Scan/runtime/structured_failures.py"),
        Path("Virus_Scan/runtime/telemetry.py"),
        Path("Virus_Scan/runtime/stabilization_arbitration.py"),
        Path("Virus_Scan/runtime/stability_policy.py"),
        Path("Virus_Scan/runtime/topology_stabilization.py"),
        Path("Virus_Scan/runtime/temporal_state.py"),
        Path("Virus_Scan/runtime/telemetry_governance.py"),
        Path("Virus_Scan/runtime/state_domains.py"),
        Path("Virus_Scan/runtime/transactional_state.py"),
        Path("Virus_Scan/runtime/yara_rules_state.py"),
        Path("Virus_Scan/runtime/scanner_governance.py"),
        Path("Virus_Scan/runtime/scheduler_runtime_state.py"),
    ]

    for source_path in repaired_sources:
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=source_path.as_posix())
        assert [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []

    dependency_source = repaired_sources[0].read_text(encoding="utf-8")
    assert "vars(" not in repaired_sources[1].read_text(encoding="utf-8")
    assert 'f"{field_name}' not in dependency_source
    assert "self._records.items()" not in repaired_sources[2].read_text(encoding="utf-8")
