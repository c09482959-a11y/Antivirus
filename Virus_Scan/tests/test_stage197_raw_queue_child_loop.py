import ast
from pathlib import Path
from typing import Iterator

from Virus_Scan.scheduler.execution.process_queue_loop import (
    QueueChildIdleDecisionDependencies,
    queue_child_idle_decision,
)


def _deps(**overrides):
    values = {
        "consume_retire": lambda _q: False,
        "raw_has_live_work": lambda _q: False,
        "feed_is_complete": lambda _q: True,
        "raw_queue_enabled": lambda: False,
        "environ_get": lambda _k, default: default,
    }
    values.update(overrides)
    return QueueChildIdleDecisionDependencies(**values)


def test_queue_child_idle_decision_retire_precedes_raw_wait():
    deps = _deps(
        consume_retire=lambda _q: True,
        raw_has_live_work=lambda _q: True,
        raw_queue_enabled=lambda: True,
    )
    assert queue_child_idle_decision("/tmp/q", deps) == "retire"


def test_queue_child_idle_decision_waits_for_raw_live_work():
    deps = _deps(raw_has_live_work=lambda _q: True, raw_queue_enabled=lambda: True)
    assert queue_child_idle_decision("/tmp/q", deps) == "wait_raw"


def test_queue_child_idle_decision_waits_for_dynamic_feed():
    deps = _deps(feed_is_complete=lambda _q: False)
    assert queue_child_idle_decision("/tmp/q", deps) == "wait_feed"


def test_queue_child_idle_decision_exits_when_disabled_or_complete():
    assert queue_child_idle_decision("/tmp/q", _deps()) == "exit"
    assert queue_child_idle_decision(None, _deps()) == "exit"


class _HookBomb:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def _hit(self, name: str):
        self.calls.append(name)
        raise AssertionError(name)

    def __bool__(self):
        return self._hit("__bool__")

    def __float__(self):
        return self._hit("__float__")

    def __format__(self, _spec):
        return self._hit("__format__")

    def __int__(self):
        return self._hit("__int__")

    def __iter__(self) -> Iterator[object]:
        return self._hit("__iter__")

    def __repr__(self):
        return self._hit("__repr__")

    def __str__(self):
        return self._hit("__str__")


def test_queue_child_env_values_reject_hostile_conversion_hooks():
    hostile = _HookBomb()
    deps = _deps(environ_get=lambda _key, _default: hostile)

    assert queue_child_idle_decision("/tmp/q", deps) == "exit"
    assert hostile.calls == []


def test_queue_child_loop_architecture_blocks_raw_env_conversions():
    source = (Path(__file__).resolve().parents[1] / "scheduler" / "execution" / "process_queue_loop.py").read_text()
    tree = ast.parse(source)
    checked = {
        "queue_child_idle_decision",
        "_queue_child_env_enabled",
    }
    forbidden_names = {"bool", "float", "int", "repr", "str", "vars"}
    forbidden_attrs = {"lower"}
    violations: list[tuple[str, int, str]] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in checked:
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id in forbidden_names:
                    violations.append((node.name, child.lineno, child.func.id))
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr in forbidden_attrs:
                    violations.append((node.name, child.lineno, child.func.attr))
    assert violations == []
