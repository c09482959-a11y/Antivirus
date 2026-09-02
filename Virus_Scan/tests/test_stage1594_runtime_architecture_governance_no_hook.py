from __future__ import annotations

from Virus_Scan.runtime.architecture_governance import (
    GovernanceTopologyAudit,
    SchemaEvolutionReport,
    SemanticOwnershipReport,
    causal_architecture_visualization,
    governance_topology_audit,
    schema_evolution_report,
    semantic_ownership_report,
)


class HostileEvent:
    touched = 0

    @property
    def domain(self):  # pragma: no cover - failure proves property traversal
        type(self).touched += 1
        raise AssertionError("domain property touched")

    def as_dict(self):  # pragma: no cover - failure proves unsafe as_dict
        type(self).touched += 1
        raise AssertionError("as_dict touched")

    def __iter__(self):  # pragma: no cover - failure proves unsafe iteration
        type(self).touched += 1
        raise AssertionError("iter touched")

    def __str__(self):  # pragma: no cover - failure proves unsafe stringification
        type(self).touched += 1
        raise AssertionError("str touched")

    def __repr__(self):  # pragma: no cover - failure proves unsafe repr
        type(self).touched += 1
        raise AssertionError("repr touched")


class HostileContracts(dict):
    touched = 0

    def items(self):  # pragma: no cover - failure proves mapping hook traversal
        type(self).touched += 1
        raise AssertionError("items touched")

    def get(self, key, default=None):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("get touched")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("iter touched")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("bool touched")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("str touched")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("repr touched")


class HostileText:
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("str touched")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("repr touched")


class HostileEvents(list):
    touched = 0

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("iter touched")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("bool touched")



def test_stage1594_architecture_governance_rejects_hostile_event_without_hooks() -> None:
    HostileEvent.touched = 0
    event = HostileEvent()

    semantic = semantic_ownership_report([event]).as_dict()
    schema = schema_evolution_report([event], {}).as_dict()
    topology = governance_topology_audit([event], {}).as_dict()
    visual = causal_architecture_visualization([event], {}, max_events=4)

    assert HostileEvent.touched == 0
    assert semantic["ok"] is False
    assert any("unsupported_event" in item for item in semantic["orphaned_concepts"])
    assert any("event_unavailable" in item for item in schema["unknown_contracts"])
    assert any("event_unavailable" in item for item in topology["hidden_dependencies"])
    assert visual["nodes"][0]["domain"] == "governance"
    assert visual["nodes"][0]["kind"] == "unsupported_event"



def test_stage1594_architecture_governance_rejects_hostile_contract_mapping_without_hooks() -> None:
    HostileContracts.touched = 0
    event = {"seq": 7, "domain": "scheduler", "kind": "queued", "owner": "scheduler", "schema_version": 1}

    schema = schema_evolution_report([event], HostileContracts()).as_dict()
    topology = governance_topology_audit([event], HostileContracts()).as_dict()

    assert HostileContracts.touched == 0
    assert schema["ok"] is False
    assert any(item.startswith("contracts_unavailable:HostileContracts") for item in schema["unknown_contracts"])
    assert any(item.startswith("contracts_unavailable:HostileContracts") for item in topology["hidden_dependencies"])



def test_stage1594_architecture_governance_dataclass_reports_do_not_stringify_hostile_fields() -> None:
    HostileText.touched = 0

    semantic = SemanticOwnershipReport(True, duplicated_concepts=(HostileText(),)).as_dict()
    schema = SchemaEvolutionReport(True, unknown_contracts=(HostileText(),), migration_required=(HostileText(),)).as_dict()
    topology = GovernanceTopologyAudit(True, hidden_dependencies=(HostileText(),), unstable_paths=(HostileText(),)).as_dict()

    assert HostileText.touched == 0
    assert semantic["duplicated_concepts"] == ["unsupported_text:HostileText"]
    assert schema["unknown_contracts"] == ["unsupported_text:HostileText"]
    assert schema["migration_required"] == ["unsupported_text:HostileText"]
    assert topology["hidden_dependencies"] == ["unsupported_text:HostileText"]
    assert topology["unstable_paths"] == ["unsupported_text:HostileText"]



def test_stage1594_architecture_governance_preserves_exact_builtin_event_behavior() -> None:
    event = {"seq": 1, "domain": "scheduler", "kind": "queued", "owner": "scheduler", "schema_version": 1}
    contracts = {"scheduler:queued": {"version": 1}}

    semantic = semantic_ownership_report([event]).as_dict()
    schema = schema_evolution_report([event], contracts).as_dict()
    topology = governance_topology_audit([event], contracts).as_dict()
    visual = causal_architecture_visualization([event], contracts, max_events=4)

    assert semantic["ok"] is True
    assert schema["ok"] is True
    assert topology["ok"] is True
    assert visual["domain_counts"] == {"scheduler": 1}
    assert visual["topology_audit"]["ok"] is True



def test_stage1594_architecture_governance_rejects_hostile_event_sequence_without_iterating() -> None:
    HostileEvents.touched = 0

    semantic = semantic_ownership_report(HostileEvents([{"domain": "scheduler"}])).as_dict()

    assert HostileEvents.touched == 0
    assert semantic["ok"] is False
    assert any("non_materializable_architecture_event_sequence" in item for item in semantic["orphaned_concepts"])
