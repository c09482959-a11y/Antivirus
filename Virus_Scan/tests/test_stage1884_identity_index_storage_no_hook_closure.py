from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan.scheduler.queue import identity_index_storage


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    fspath_calls = 0
    getattribute_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.fspath_calls = 0
        cls.getattribute_calls = 0

    @classmethod
    def total_calls(cls) -> int:
        return (
            cls.str_calls
            + cls.repr_calls
            + cls.format_calls
            + cls.bool_calls
            + cls.iter_calls
            + cls.fspath_calls
            + cls.getattribute_calls
        )

    def __getattribute__(self, name: str):  # pragma: no cover - forbidden
        type(self).getattribute_calls += 1
        raise RuntimeError(name)

    def __str__(self):  # pragma: no cover - forbidden
        type(self).str_calls += 1
        raise RuntimeError("str")

    def __repr__(self):  # pragma: no cover - forbidden
        type(self).repr_calls += 1
        raise RuntimeError("repr")

    def __format__(self, spec):  # pragma: no cover - forbidden
        type(self).format_calls += 1
        raise RuntimeError("format")

    def __bool__(self):  # pragma: no cover - forbidden
        type(self).bool_calls += 1
        raise RuntimeError("bool")

    def __iter__(self):  # pragma: no cover - forbidden
        type(self).iter_calls += 1
        raise RuntimeError("iter")

    def __fspath__(self):  # pragma: no cover - forbidden
        type(self).fspath_calls += 1
        raise RuntimeError("fspath")


def _source_tree() -> ast.Module:
    root = Path(__file__).resolve().parents[2]
    source = root / "Virus_Scan" / "scheduler" / "queue" / "identity_index_storage.py"
    return parse_python_file(source)


def test_stage1884_identity_index_storage_rejects_hostile_key_parts_without_hooks(tmp_path):
    HostileValue.reset()
    records: list[tuple[str, str]] = []

    digest = identity_index_storage.key_digest(
        (tmp_path, HostileValue()),
        lambda where, exc: records.append((where, type(exc).__name__)),
    )

    assert digest is None
    assert records == [("key_part_rejected", "ValueError")]
    assert HostileValue.total_calls() == 0


def test_stage1884_identity_index_storage_rejects_hostile_queue_dir_without_hooks():
    HostileValue.reset()
    records: list[tuple[str, str]] = []

    queue_dir = identity_index_storage.queue_dir_from_key(
        (HostileValue(),),
        lambda where, exc: records.append((where, type(exc).__name__)),
    )

    assert queue_dir is None
    assert records == [("queue_dir_key_failed", "ValueError")]
    assert HostileValue.total_calls() == 0


def test_stage1884_identity_index_storage_has_no_exception_handler_sentinel_returns():
    violations: list[tuple[int, str]] = []
    for node in ast.walk(_source_tree()):
        if isinstance(node, ast.ExceptHandler):
            for child in ast.walk(node):
                if isinstance(child, ast.Return):
                    violations.append((child.lineno, ast.unparse(child.value) if child.value else ""))
    assert violations == []


def test_stage1884_identity_index_storage_has_no_fstring_materialization():
    joined_strings = [node.lineno for node in ast.walk(_source_tree()) if isinstance(node, ast.JoinedStr)]
    assert joined_strings == []
