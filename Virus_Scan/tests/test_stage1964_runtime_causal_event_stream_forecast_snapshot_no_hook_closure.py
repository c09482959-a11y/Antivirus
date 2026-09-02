
"""Stage1964 causal event stream forecast/snapshot no-hook closure regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.runtime.causal_event_stream import EventBus


class Stage1964HostileText:
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


def test_stage1964_causal_event_stream_source_closes_forecast_snapshot_clusters() -> None:
    source = read_python_file(Path("Virus_Scan/runtime/causal_event_stream.py"))
    forbidden = (
        "max(lineages.values(), default=0)",
        "max(self._children.values(), default=0)",
        "sum(self._lineage_pruned.values())",
        "child_counts.items()",
        "sum(child_counts.values())",
        "self._lineage_counts.values()",
        "max(child_counts.values(), default=0)",
        "sum(b.suppressed for b in self._budgets.values())",
        "sorted(self._budgets.items())",
        'producers[f"{ev.domain}:{ev.kind}"]',
        'producers.get(f"{ev.domain}:{ev.kind}"',
        'f"{parent.domain}:{parent.kind}->{ev.domain}:{ev.kind}"',
        "dict(sorted(producers.items()))",
        "dict(sorted(edges.items()))",
        "self._children.items()",
        "dict(sorted(self._suppressed_reasons.items()))",
        "default=causal_text, allow_nan=False",
        '"label": f"{ev.domain}:{ev.kind}"',
    )
    assert not [pattern for pattern in forbidden if pattern in source]


def test_stage1964_forecasts_snapshots_and_visualization_use_owned_routes() -> None:
    Stage1964HostileText.touched = 0
    hostile = Stage1964HostileText()
    bus = EventBus(max_fanout_per_parent=2, max_events_per_workload=8)

    root = bus.emit("runtime", "exports_registered", {"count": 1}, workload_id=hostile)
    child = bus.emit(
        "runtime",
        "exports_registered",
        {"count": 2},
        parent_seq=root.seq,
        workload_id=hostile,
    )
    bus.emit(
        "telemetry",
        "burst_suppressed",
        {"payload": "value"},
        lineage_id=child.lineage_id,
        parent_seq=child.seq,
        workload_id=hostile,
    )
    bus.emit("runtime", "exports_registered", {"count": 3}, parent_seq=9999)

    pressure = bus.replay_lineage_pressure()
    topology = bus.causal_topology_forecast()
    topology_pressure = bus.topology_pressure_forecast()
    budgets = bus.budget_snapshot()
    dependencies = bus.dependency_snapshot()
    invariants = bus.invariant_snapshot()
    digest = bus.replay_digest()
    visualization = bus.causal_trace_visualization(max_events=8)

    assert pressure["event_count"] >= 3
    assert "pressure" in pressure
    assert topology["event_count"] >= 3
    assert "anomaly_probability" in topology
    assert topology_pressure["event_count"] >= 3
    assert any(key.startswith("causal_text_unavailable:") for key in budgets)
    assert dependencies["event_types"]
    assert dependencies["edges"]
    assert "suppressed_reasons" in invariants
    assert digest
    assert visualization["nodes"][0]["label"]
    assert Stage1964HostileText.touched == 0
