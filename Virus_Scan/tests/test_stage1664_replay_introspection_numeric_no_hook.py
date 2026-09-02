"""Stage 1664: replay introspection numeric boundaries reject hooks and truncation."""

from Virus_Scan.models.replay_introspection import (
    ReplayBudget,
    ReplayNode,
    garbage_collect_replay,
    validate_replay_lineage,
)


class _HostileReplayNumeric:
    float_calls = 0
    int_calls = 0
    bool_calls = 0

    def __float__(self):  # pragma: no cover - failure proves hook execution
        type(self).float_calls += 1
        raise AssertionError("caller-owned __float__ must not execute")

    def __int__(self):  # pragma: no cover - failure proves hook execution
        type(self).int_calls += 1
        raise AssertionError("caller-owned __int__ must not execute")

    def __bool__(self):  # pragma: no cover - failure proves truthiness execution
        type(self).bool_calls += 1
        raise AssertionError("caller-owned __bool__ must not execute")


def _reset_hostile_numeric() -> None:
    _HostileReplayNumeric.float_calls = 0
    _HostileReplayNumeric.int_calls = 0
    _HostileReplayNumeric.bool_calls = 0


def test_stage1664_replay_node_influence_rejects_numeric_hooks_without_calling_them():
    _reset_hostile_numeric()

    node = ReplayNode("child", "root", ("tag",), _HostileReplayNumeric(), "origin", "reason")

    assert node.influence == 0.0
    assert _HostileReplayNumeric.float_calls == 0
    assert _HostileReplayNumeric.int_calls == 0
    assert _HostileReplayNumeric.bool_calls == 0


def test_stage1664_replay_budget_max_nodes_rejects_numeric_hooks_without_calling_them():
    _reset_hostile_numeric()
    nodes = [ReplayNode(str(index), influence=1.0) for index in range(3)]
    budget = ReplayBudget(max_nodes=_HostileReplayNumeric())

    kept = garbage_collect_replay(nodes, budget=budget)

    assert [node.node_id for node in kept] == ["0", "1", "2"]
    assert _HostileReplayNumeric.float_calls == 0
    assert _HostileReplayNumeric.int_calls == 0
    assert _HostileReplayNumeric.bool_calls == 0


def test_stage1664_replay_budget_max_nodes_does_not_truncate_non_integral_float():
    nodes = [ReplayNode(str(index), influence=1.0) for index in range(3)]

    kept_non_integral = garbage_collect_replay(nodes, budget=ReplayBudget(max_nodes=2.9))
    kept_integral = garbage_collect_replay(nodes, budget=ReplayBudget(max_nodes=2.0))

    assert [node.node_id for node in kept_non_integral] == ["0", "1", "2"]
    assert [node.node_id for node in kept_integral] == ["0", "1"]


def test_stage1664_replay_lineage_limits_reject_numeric_hooks_with_evidence():
    _reset_hostile_numeric()
    nodes = [ReplayNode("root"), ReplayNode("child", "root")]
    hostile = _HostileReplayNumeric()

    result = validate_replay_lineage(
        nodes,
        max_depth=hostile,
        max_fanout=hostile,
        max_nodes=hostile,
    )

    assert result["ok"] is False
    assert "max_depth_limit_unavailable" in result["errors"]
    assert "max_fanout_limit_unavailable" in result["errors"]
    assert "max_nodes_limit_unavailable" in result["errors"]
    assert _HostileReplayNumeric.float_calls == 0
    assert _HostileReplayNumeric.int_calls == 0
    assert _HostileReplayNumeric.bool_calls == 0
