from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.tests.support.static_inventory import parse_python_file
from Virus_Scan.scheduler.queue import identity_index


class HostileValue:
    str_calls = 0
    repr_calls = 0
    bool_calls = 0
    float_calls = 0
    getattribute_calls = 0
    fspath_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.bool_calls = 0
        cls.float_calls = 0
        cls.getattribute_calls = 0
        cls.fspath_calls = 0

    @classmethod
    def total_calls(cls) -> int:
        return (
            cls.str_calls
            + cls.repr_calls
            + cls.bool_calls
            + cls.float_calls
            + cls.getattribute_calls
            + cls.fspath_calls
        )

    def __getattribute__(self, name: str):  # pragma: no cover - forbidden hook
        type(self).getattribute_calls += 1
        raise RuntimeError(name)

    def __str__(self):  # pragma: no cover - forbidden hook
        type(self).str_calls += 1
        raise RuntimeError("str")

    def __repr__(self):  # pragma: no cover - forbidden hook
        type(self).repr_calls += 1
        raise RuntimeError("repr")

    def __bool__(self):  # pragma: no cover - forbidden hook
        type(self).bool_calls += 1
        raise RuntimeError("bool")

    def __float__(self):  # pragma: no cover - forbidden hook
        type(self).float_calls += 1
        raise RuntimeError("float")

    def __fspath__(self):  # pragma: no cover - forbidden hook
        type(self).fspath_calls += 1
        raise RuntimeError("fspath")


def _function_returns(tree: ast.AST, names: set[str]) -> list[tuple[str, int, str]]:
    violations: list[tuple[str, int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in names:
            for child in ast.walk(node):
                if isinstance(child, ast.Return):
                    if child.value is None:
                        violations.append((node.name, child.lineno, "bare_return"))
                    elif isinstance(child.value, ast.Constant) and child.value.value is None:
                        violations.append((node.name, child.lineno, "return_None"))
    return violations


def test_stage2094_identity_index_public_scalar_contracts_preserve_legacy_shape(tmp_path: Path) -> None:
    key = (tmp_path, "pending")

    set_outcome = identity_index.set_index_entry_outcome(key, {"job-a"})
    hit_outcome = identity_index.get_index_entry_outcome(key, 60.0)

    assert set_outcome.status == "completed"
    assert set_outcome.reason == "identity_index_written"
    assert hit_outcome.status == "hit"
    assert hit_outcome.reason == "identity_index_entry_found"
    assert hit_outcome.identities == frozenset({"job-a"})
    assert identity_index.get_index_entry(key, 60.0) == {"job-a"}


def test_stage2094_identity_index_rejections_are_replayable_without_hooks(tmp_path: Path) -> None:
    key = (tmp_path, "pending")
    identity_index.set_index_entry_outcome(key, {"job-a"})
    HostileValue.reset()

    ttl_outcome = identity_index.get_index_entry_outcome(key, HostileValue())
    note_outcome = identity_index.note_identity_for_queue_outcome(HostileValue(), "job-b")
    invalidate_outcome = identity_index.invalidate_queue_outcome(HostileValue())

    assert ttl_outcome.status == "rejected"
    assert ttl_outcome.reason == "queue_identity_index_ttl_rejected"
    assert note_outcome.status == "failed"
    assert note_outcome.reason == "queue_dir_rejected"
    assert invalidate_outcome.status == "failed"
    assert invalidate_outcome.reason == "invalidate_queue_dir_rejected"
    assert HostileValue.total_calls() == 0


def test_stage2094_identity_index_missing_and_expired_states_are_typed(tmp_path: Path) -> None:
    missing_outcome = identity_index.get_index_entry_outcome((tmp_path, "missing"), 60.0)
    identity_index.set_index_entry_outcome((tmp_path, "pending"), {"job-a"})
    expired_outcome = identity_index.get_index_entry_outcome((tmp_path, "pending"), 0.0)

    assert missing_outcome.status in {"miss", "rejected"}
    assert missing_outcome.reason in {"identity_index_payload_missing", "identity_index_path_unavailable"}
    assert expired_outcome.status == "expired"
    assert expired_outcome.reason == "identity_index_entry_expired"


def test_stage2094_identity_index_cluster_removed_unsafe_return_and_alias_surfaces() -> None:
    root = Path(__file__).resolve().parents[2]
    source = root / "Virus_Scan" / "scheduler" / "queue" / "identity_index.py"
    text = source.read_text(encoding="utf-8")
    tree = parse_python_file(source)

    target_functions = {
        "note_identity_for_queue",
        "get_index_entry",
        "invalidate_queue",
        "set_index_entry",
    }
    assert _function_returns(tree, target_functions) == []
    assert "from Virus_Scan.scheduler.queue.identity_index_storage import" not in text
    assert "def _index_path_for_key" not in text
    assert "def _read_index" not in text
    assert "def _identity_snapshot" not in text
    assert "def _write_index" not in text
    assert "def _prune_index_dir" not in text
    assert "def _identity_index_nonnegative_float" not in text
