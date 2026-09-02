from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep import InMemoryTimeoutSweepResult


def _imports_from(path: str) -> list[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
    return modules


def test_timeout_sweep_uses_injected_worker_heartbeat_ingester_boundary():
    modules = _imports_from("Virus_Scan/scheduler/timeout/inmemory_timeout_sweep.py")
    assert not any(module.startswith("Virus_Scan.scheduler.workers") for module in modules)
    source = read_python_file(Path("Virus_Scan/scheduler/timeout/inmemory_timeout_sweep.py"))
    assert "heartbeat_ingester" in source
    assert "shared_heartbeats_observed" in InMemoryTimeoutSweepResult.__dataclass_fields__
    assert "shared_heartbeat_cancel_requests" in InMemoryTimeoutSweepResult.__dataclass_fields__


def test_queue_orphan_recovery_uses_injected_worker_process_boundaries():
    orphan_modules = _imports_from("Virus_Scan/scheduler/queue/orphan_recovery.py")
    claim_state_modules = _imports_from("Virus_Scan/scheduler/queue/orphan_recovery_claim_state.py")
    assert not any(module.startswith("Virus_Scan.scheduler.workers") for module in orphan_modules)
    assert not any(module.startswith("Virus_Scan.scheduler.workers") for module in claim_state_modules)
    orphan_source = read_python_file(Path("Virus_Scan/scheduler/queue/orphan_recovery.py"))
    claim_source = read_python_file(Path("Virus_Scan/scheduler/queue/orphan_recovery_claim_state.py"))
    assert "worker_terminator" in orphan_source
    assert "worker_liveness_checker" in orphan_source
    assert "worker_liveness_checker" in claim_source


def test_timeout_escalation_uses_injected_worker_termination_callbacks():
    for path in (
        "Virus_Scan/scheduler/timeout/escalation_engine.py",
        "Virus_Scan/scheduler/timeout/inmemory_memory_toxicity.py",
    ):
        modules = _imports_from(path)
        assert not any(module.startswith("Virus_Scan.scheduler.workers") for module in modules)
    escalation = read_python_file(Path("Virus_Scan/scheduler/timeout/escalation_engine.py"))
    toxicity = read_python_file(Path("Virus_Scan/scheduler/timeout/inmemory_memory_toxicity.py"))
    assert "worker_terminator" in escalation
    assert "idle_worker_terminator" in toxicity
