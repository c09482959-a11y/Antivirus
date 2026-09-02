from __future__ import annotations

from pathlib import Path

from Virus_Scan.runtime.architecture_governance import (
    GovernanceTopologyAudit,
    SchemaEvolutionReport,
    SemanticOwnershipReport,
    causal_architecture_visualization,
    governance_topology_audit,
    schema_evolution_report,
    semantic_ownership_report,
)

RUNTIME_ROOT = Path(__file__).resolve().parents[1] / "runtime"


class Stage1961HostileText:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - failure proves caller-owned string hook
        type(self).touched += 1
        raise AssertionError("hostile text str touched")

    def __repr__(self):  # pragma: no cover - failure proves caller-owned repr hook
        type(self).touched += 1
        raise AssertionError("hostile text repr touched")

    def __format__(self, _spec):  # pragma: no cover - failure proves caller-owned format hook
        type(self).touched += 1
        raise AssertionError("hostile text format touched")

    def __bool__(self):  # pragma: no cover - failure proves truth hook traversal
        type(self).touched += 1
        raise AssertionError("hostile text bool touched")


class Stage1961HostileEvent:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    @property
    def domain(self):  # pragma: no cover - failure proves attribute traversal
        type(self).touched += 1
        raise AssertionError("hostile event domain touched")

    def as_dict(self):  # pragma: no cover - failure proves adapter traversal
        type(self).touched += 1
        raise AssertionError("hostile event as_dict touched")

    def __iter__(self):  # pragma: no cover - failure proves iteration hook
        type(self).touched += 1
        raise AssertionError("hostile event iter touched")

    def __str__(self):  # pragma: no cover - failure proves string hook
        type(self).touched += 1
        raise AssertionError("hostile event str touched")

    def __repr__(self):  # pragma: no cover - failure proves repr hook
        type(self).touched += 1
        raise AssertionError("hostile event repr touched")

    def __format__(self, _spec):  # pragma: no cover - failure proves format hook
        type(self).touched += 1
        raise AssertionError("hostile event format touched")


class Stage1961HostileContracts(dict):
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def items(self):  # pragma: no cover - failure proves mapping hook traversal
        type(self).touched += 1
        raise AssertionError("hostile contracts items touched")

    def get(self, _key, _default=None):  # pragma: no cover - failure proves mapping hook traversal
        type(self).touched += 1
        raise AssertionError("hostile contracts get touched")

    def __iter__(self):  # pragma: no cover - failure proves iteration hook
        type(self).touched += 1
        raise AssertionError("hostile contracts iter touched")

    def __bool__(self):  # pragma: no cover - failure proves bool hook
        type(self).touched += 1
        raise AssertionError("hostile contracts bool touched")

    def __str__(self):  # pragma: no cover - failure proves string hook
        type(self).touched += 1
        raise AssertionError("hostile contracts str touched")

    def __repr__(self):  # pragma: no cover - failure proves repr hook
        type(self).touched += 1
        raise AssertionError("hostile contracts repr touched")


class Stage1961HostileEvents(list):
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __iter__(self):  # pragma: no cover - failure proves unsafe list subclass iteration
        type(self).touched += 1
        raise AssertionError("hostile events iter touched")

    def __bool__(self):  # pragma: no cover - failure proves unsafe list subclass truthiness
        type(self).touched += 1
        raise AssertionError("hostile events bool touched")

    def __str__(self):  # pragma: no cover - failure proves unsafe stringification
        type(self).touched += 1
        raise AssertionError("hostile events str touched")

    def __repr__(self):  # pragma: no cover - failure proves unsafe repr
        type(self).touched += 1
        raise AssertionError("hostile events repr touched")


def test_stage1961_architecture_governance_source_closes_current_backlog_routes() -> None:
    source = (RUNTIME_ROOT / "architecture_governance.py").read_text(encoding="utf-8")
    forbidden = (
        'f"unsupported_sequence:',
        'f"unsupported_text:',
        'f"contracts_unavailable:',
        'f"contract_key_unavailable:',
        'f"unsupported_event:',
        'f"{domain}:{kind}',
        'f"{key}:event_unavailable:',
        'f"{key}:event_v',
        'f"{src}:event_unavailable:',
        'f"{parent_domain}:{parent_kind}',
        '"label": f"',
        "concept_to_event_types.setdefault",
        "concept_to_event_types.items()",
        "domain_counts.items()",
    )
    for snippet in forbidden:
        assert snippet not in source


def test_stage1961_architecture_governance_rejects_hostile_report_text_without_hooks() -> None:
    Stage1961HostileText.reset()
    hostile = Stage1961HostileText()

    semantic = SemanticOwnershipReport(True, duplicated_concepts=(hostile,)).as_dict()
    schema = SchemaEvolutionReport(True, unknown_contracts=(hostile,), migration_required=(hostile,)).as_dict()
    topology = GovernanceTopologyAudit(True, hidden_dependencies=(hostile,), unstable_paths=(hostile,)).as_dict()

    assert Stage1961HostileText.touched == 0
    assert semantic["duplicated_concepts"] == ["unsupported_text:Stage1961HostileText"]
    assert schema["unknown_contracts"] == ["unsupported_text:Stage1961HostileText"]
    assert schema["migration_required"] == ["unsupported_text:Stage1961HostileText"]
    assert topology["hidden_dependencies"] == ["unsupported_text:Stage1961HostileText"]
    assert topology["unstable_paths"] == ["unsupported_text:Stage1961HostileText"]


def test_stage1961_architecture_governance_rejects_hostile_event_and_contract_routes() -> None:
    Stage1961HostileEvent.reset()
    Stage1961HostileContracts.reset()
    event = Stage1961HostileEvent()
    contracts = Stage1961HostileContracts()

    semantic = semantic_ownership_report([event]).as_dict()
    schema = schema_evolution_report([event], contracts).as_dict()
    topology = governance_topology_audit([event], contracts).as_dict()
    visual = causal_architecture_visualization([event], contracts, max_events=4)

    assert Stage1961HostileEvent.touched == 0
    assert Stage1961HostileContracts.touched == 0
    assert any(item.startswith("unsupported_event:") for item in semantic["orphaned_concepts"])
    assert any(item.startswith("contracts_unavailable:Stage1961HostileContracts") for item in schema["unknown_contracts"])
    assert any("event_unavailable" in item for item in schema["unknown_contracts"])
    assert any(item.startswith("contracts_unavailable:Stage1961HostileContracts") for item in topology["hidden_dependencies"])
    assert any("event_unavailable" in item for item in topology["hidden_dependencies"])
    assert visual["nodes"][0]["label"] == "governance:unsupported_event"


def test_stage1961_architecture_governance_preserves_exact_builtin_labels_and_counts() -> None:
    parent = {"seq": 1, "domain": "scheduler", "kind": "queued", "owner": "scheduler", "schema_version": 1}
    child = {"seq": 2, "domain": "telemetry", "kind": "emitted", "owner": "telemetry", "schema_version": 2, "parent_seq": 1}
    contracts = {"scheduler:queued": {"version": 1}, "telemetry:emitted": {"version": 1}}

    semantic = semantic_ownership_report([parent, child]).as_dict()
    schema = schema_evolution_report([parent, child], contracts).as_dict()
    topology = governance_topology_audit([parent, child], contracts).as_dict()
    visual = causal_architecture_visualization([parent, child], contracts, max_events=4)

    assert semantic["ok"] is True
    assert schema["migration_required"] == ["telemetry:emitted:event_v2:contract_v1"]
    assert topology["unstable_paths"] == ["scheduler:queued->telemetry:emitted"]
    assert visual["nodes"][0]["label"] == "scheduler:queued"
    assert visual["nodes"][1]["label"] == "telemetry:emitted"
    assert visual["domain_counts"] == {"scheduler": 1, "telemetry": 1}


def test_stage1961_architecture_governance_rejects_hostile_event_sequence_without_iterating() -> None:
    Stage1961HostileEvents.reset()

    semantic = semantic_ownership_report(Stage1961HostileEvents([{"domain": "scheduler"}])).as_dict()

    assert Stage1961HostileEvents.touched == 0
    assert semantic["ok"] is False
    assert semantic["orphaned_concepts"] == ["unsupported_event:non_materializable_architecture_event_sequence:Stage1961HostileEvents"]
