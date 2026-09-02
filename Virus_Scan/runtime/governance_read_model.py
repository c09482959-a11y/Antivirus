"""Governance read model isolated from RuntimeRoot mutation coordination."""
from __future__ import annotations
from typing import ClassVar, Mapping
from types import MappingProxyType
from .stabilization_arbitration import arbitrate_stabilization
from .stability_policy import decide_stabilization
from .governance_recovery import verify_governance_convergence, plan_adaptive_rollback
from .architecture_governance import causal_architecture_visualization, governance_topology_audit, schema_evolution_report, semantic_ownership_report
from .emergent_simulation import simulate_emergent_behaviors, immutable_orchestration_invariants
from .replay_introspection import validate_replay_integrity, build_replay_graph
from .governance_planes import governance_planes_snapshot


class _RuntimeRootTypeRegistry:
    root_type: ClassVar[type[object] | None] = None


def _register_runtime_root_type(root_type: type[object]) -> None:
    if type(root_type) is not type:
        exception_message = "runtime root owner type must be an exact class"
        raise TypeError(exception_message)
    if _RuntimeRootTypeRegistry.root_type is not None and _RuntimeRootTypeRegistry.root_type is not root_type:
        exception_message = "runtime root owner type already registered"
        raise RuntimeError(exception_message)
    _RuntimeRootTypeRegistry.root_type = root_type


def _semantic_budget_key_text(key: object) -> str | None:
    if type(key) is not tuple:
        return None
    parts: list[str] = []
    for part in key:
        if type(part) is not str:
            return None
        parts.append(str.__str__(part))
    return str.join("|", parts)


def _semantic_budget_snapshot(budget: Mapping[tuple[str, str, str], float]) -> dict[str, float]:
    if type(budget) is not dict:
        return {}
    rows: list[tuple[str, float]] = []
    for key, value in dict.items(budget):
        key_text = _semantic_budget_key_text(key)
        if key_text is None or type(value) not in (int, float) or type(value) is bool:
            continue
        rows.append((key_text, value + 0.0))
    return dict(sorted(rows, key=lambda item: item[0]))


def _exact_mapping_snapshot(value: object) -> dict[str, object]:
    if type(value) is not dict:
        return {}
    rows = tuple((key, item) for key, item in dict.items(value) if type(key) is str)
    return {str.__str__(key): item for key, item in sorted(rows, key=lambda row: str.__str__(row[0]))}


def _domains_snapshot(domains: object) -> dict[str, object]:
    if type(domains) is not dict:
        return {}
    rows = tuple((name, dom) for name, dom in dict.items(domains) if type(name) is str)
    out: dict[str, object] = {}
    for name, dom in sorted(rows, key=lambda row: str.__str__(row[0])):
        volatility = dom.volatility()
        out[str.__str__(name)] = {
            'generation': dom.generation,
            'mutation_count': dom.mutation_count,
            'volatility': _exact_mapping_snapshot(volatility),
        }
    return out


def _replay_graph_summary(events: object) -> dict[str, object]:
    graph = build_replay_graph(events)
    if type(graph) is not dict:
        return {}
    return {
        'node_count': dict.get(graph, 'node_count'),
        'edge_count': dict.get(graph, 'edge_count'),
    }


def _topology_snapshot(bus: object) -> Mapping[str, object]:
    return MappingProxyType({
        'event_dependencies': bus.dependency_snapshot(),
        'topology_pressure_forecast': bus.topology_pressure_forecast(),
        'causal_topology_forecast': bus.causal_topology_forecast(),
        'causal_trace_visualization': bus.causal_trace_visualization(max_events=512),
    })


def _replay_snapshot(bus: object) -> Mapping[str, object]:
    events = bus.snapshot()
    compressed_causal_trace = bus.compressed_causal_trace(max_events=512)
    return MappingProxyType({
        'causal_replay_snapshot': bus.deterministic_snapshot().as_dict(),
        'replay_lineage_pressure': bus.replay_lineage_pressure(),
        'compressed_replay': bus.compressed_replay()[-256:],
        'replay_integrity': validate_replay_integrity(events).as_dict(),
        'replay_graph_summary': _replay_graph_summary(events),
        'compressed_causal_tracing': compressed_causal_trace,
        'compressed_causal_trace': compressed_causal_trace,
    })


def build_governance_read_model(root: object) -> Mapping[str, object]:
    if _RuntimeRootTypeRegistry.root_type is None or type(root) is not _RuntimeRootTypeRegistry.root_type:
        exception_message = "governance read model root must be RuntimeRoot"
        raise TypeError(exception_message)
    bus = root.bus
    checkpoint = bus.deterministic_checkpoint()
    events = bus.snapshot()
    budgets = bus.budget_snapshot()
    topo = _topology_snapshot(bus)
    replay = _replay_snapshot(bus)
    contract_snapshot = bus.contract_snapshot()
    architecture_governance = causal_architecture_visualization(events, contract_snapshot, max_events=512)
    telemetry_budget = bus.telemetry_resource_budget()
    event_dependencies = topo['event_dependencies']
    topology_pressure = topo['topology_pressure_forecast']
    replay_lineage_pressure = replay['replay_lineage_pressure']
    invariant_snapshot = bus.invariant_snapshot()
    base = {
        'event_sequence': bus.sequence,
        'domains': _domains_snapshot(root.governance_read_domains()),
        'semantic_budget': _semantic_budget_snapshot(root.governance_read_semantic_budget()),
        'events': [ev.as_dict() for ev in events[-256:]],
        'event_budgets': budgets,
        'stabilization_arbitration': arbitrate_stabilization(events=events, budgets=budgets, topology=event_dependencies).as_dict(),
        **dict(topo),
        **dict(replay),
        'deterministic_checkpoint': checkpoint,
        'convergence_latency': root.convergence_latency_snapshot(),
        'immutable_state_audit': root.immutable_state_audit(),
        'stabilization_policy': decide_stabilization(invariant_snapshot=invariant_snapshot, budgets=budgets, topology=topology_pressure, lineage_pressure=replay_lineage_pressure).as_dict(),
        'event_invariants': invariant_snapshot,
        'event_contracts': contract_snapshot,
        'telemetry_resource_governance': telemetry_budget,
        'telemetry_governance': telemetry_budget,
        'telemetry_isolation': {
            'telemetry_can_trigger_replay': False,
            'telemetry_can_trigger_stabilization': False,
            'telemetry_can_trigger_governance_escalation': False,
            'telemetry_can_trigger_scheduler_escalation': False,
            'enforced_reason': 'telemetry_isolation_domain',
            },
        'causal_architecture_visualization': architecture_governance,
        'architecture_governance': architecture_governance,
        'semantic_ownership': semantic_ownership_report(events).as_dict(),
        'schema_evolution_governance': schema_evolution_report(events, contract_snapshot).as_dict(),
        'governance_topology_audit': governance_topology_audit(events, contract_snapshot).as_dict(),
        'immutable_orchestration_invariants': immutable_orchestration_invariants(events),
        'governance_planes': governance_planes_snapshot(root.governance_read_planes()),
        'circuit_breakers': _exact_mapping_snapshot(root.governance_read_circuit_breakers()),
        'pressure': _exact_mapping_snapshot(root.governance_read_pressure()),
    }
    base['governance_convergence'] = verify_governance_convergence(base).as_dict()
    base['emergent_behavior_simulation'] = simulate_emergent_behaviors(events, topology=base.get('topology_pressure_forecast'), lineage=base.get('replay_lineage_pressure'), budgets=base.get('event_budgets'), convergence=base.get('convergence_latency')).as_dict()
    base['emergent_simulation'] = base['emergent_behavior_simulation']
    base['adaptive_rollback_plan'] = plan_adaptive_rollback(base, checkpoint).as_dict()
    return MappingProxyType(base)
