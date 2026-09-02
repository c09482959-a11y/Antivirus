from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator

from Virus_Scan.scheduler.queue.inmemory_lifecycle import (
    canonical_transition_key,
    make_transition,
    replay_lifecycle,
)
from Virus_Scan.scheduler.queue.inmemory_lifecycle_decisions import (
    generation_current_decision,
    mark_retry_admitted_decision,
    terminal_transition_decision,
)


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


class _HostileMapping:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def _hit(self, name: str):
        self.calls.append(name)
        raise AssertionError(name)

    def get(self, _key, _default=None):
        return self._hit("get")

    def items(self):
        return self._hit("items")

    def keys(self):
        return self._hit("keys")

    def values(self):
        return self._hit("values")

    def __iter__(self):
        return self._hit("__iter__")

    def __len__(self):
        return self._hit("__len__")

    def __getitem__(self, _key):
        return self._hit("__getitem__")


def test_stage1791_lifecycle_transition_factory_rejects_hostile_scalars_without_hooks():
    hostile = _HookBomb()

    transition = make_transition(
        epoch=hostile,
        sequence=hostile,
        job_id=hostile,
        attempt=hostile,
        transition=hostile,
        worker_pid=hostile,
        reason=hostile,
        state=hostile,
        timestamp=hostile,
        monotonic_ns=hostile,
    )

    assert transition.epoch == 0
    assert transition.sequence == 0
    assert transition.job_id == -1
    assert transition.attempt == 0
    assert transition.transition == "unknown"
    assert transition.worker_pid == 0
    assert transition.reason == ""
    assert transition.state == ""
    assert hostile.calls == []


def test_stage1791_lifecycle_replay_rejects_hostile_mapping_without_hooks():
    hostile = _HostileMapping()

    replayed = replay_lifecycle([hostile])

    assert hostile.calls == []
    assert replayed[-1]["state"] == "lifecycle_replay_rejected"
    rejection = replayed[-1]["lifecycle_replay_rejections"][0]
    assert rejection["reason"] == "lifecycle_transition_mapping_rejected"
    assert rejection["final_json_must_record"] is True
    assert rejection["checkpoint_must_record"] is True
    assert rejection["replay_must_record"] is True


def test_stage1791_lifecycle_generation_checks_reject_hostile_attempt_without_hooks():
    hostile = _HookBomb()
    record = {"attempt": hostile, "state": "pending_retry", "retry_pending_active": True}

    assert mark_retry_admitted_decision(record, attempt=1, now=1.0).accepted is False
    assert terminal_transition_decision(record, state="done", attempt=1, now=1.0).accepted is False
    assert generation_current_decision(record, attempt=1).accepted is False
    assert hostile.calls == []
    assert record["retry_pending_active"] is True


def test_stage1791_lifecycle_key_rejects_hostile_mapping_without_hooks():
    hostile = _HostileMapping()

    assert canonical_transition_key(hostile) == (0, 0, -1, 0, "")
    assert hostile.calls == []


def test_stage1791_lifecycle_architecture_blocks_raw_conversion_and_mapping_hooks():
    root = Path(__file__).resolve().parents[1]
    files = [
        root / "scheduler" / "queue" / "inmemory_lifecycle.py",
        root / "scheduler" / "queue" / "inmemory_lifecycle_contracts.py",
    ]
    forbidden_names = {"bool", "dict", "float", "int", "repr", "str", "vars"}
    forbidden_attrs = {"get", "items", "keys", "values"}
    violations: list[tuple[str, int, str]] = []
    for file in files:
        tree = ast.parse(file.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in forbidden_names:
                violations.append((file.name, node.lineno, node.func.id))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_attrs:
                allowed_dict_get = (
                    node.func.attr == "get"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "dict"
                )
                if not allowed_dict_get:
                    violations.append((file.name, node.lineno, node.func.attr))

    assert violations == []
