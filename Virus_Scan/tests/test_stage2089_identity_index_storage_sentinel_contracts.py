"""Stage2089/Stage2100 queue identity-index storage typed sentinel guards."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

from Virus_Scan.scheduler.queue import identity_index_storage
from Virus_Scan.tests.support.static_inventory import parse_python_file

_ROOT: Final = Path(__file__).resolve().parents[2]
_TRACKED_STAGE2089_SYMBOLS: Final = frozenset(
    {
        "queue_dir_from_key",
        "key_digest",
        "index_path_for_key",
        "read_index",
        "identity_snapshot",
        "write_index",
    }
)
_STAGE2100_TYPED_SYMBOLS: Final = frozenset(
    {
        "queue_dir_from_key_decision",
        "key_digest_decision",
        "index_path_for_key_decision",
        "read_index_decision",
        "identity_snapshot_decision",
        "write_index_decision",
    }
)


class HostileValue:
    getattribute_calls = 0
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    fspath_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.getattribute_calls = 0
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.fspath_calls = 0

    @classmethod
    def total_calls(cls) -> int:
        return (
            cls.getattribute_calls
            + cls.str_calls
            + cls.repr_calls
            + cls.format_calls
            + cls.bool_calls
            + cls.iter_calls
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

    def __format__(self, spec: str):  # pragma: no cover - forbidden hook
        type(self).format_calls += 1
        raise RuntimeError("format")

    def __bool__(self):  # pragma: no cover - forbidden hook
        type(self).bool_calls += 1
        raise RuntimeError("bool")

    def __iter__(self):  # pragma: no cover - forbidden hook
        type(self).iter_calls += 1
        raise RuntimeError("iter")

    def __fspath__(self):  # pragma: no cover - forbidden hook
        type(self).fspath_calls += 1
        raise RuntimeError("fspath")


def _source_tree() -> ast.Module:
    source = _ROOT / "Virus_Scan" / "scheduler" / "queue" / "identity_index_storage.py"
    return parse_python_file(source)


def _function_returns(tree: ast.Module, names: frozenset[str]) -> list[tuple[str, int, str]]:
    returns: list[tuple[str, int, str]] = []
    for node in ast.walk(tree):
        if type(node) is ast.FunctionDef and node.name in names:
            for child in ast.walk(node):
                if type(child) is ast.Return:
                    returns.append(
                        (
                            node.name,
                            child.lineno,
                            ast.unparse(child.value) if child.value is not None else "None",
                        )
                    )
    return returns


def test_stage2089_identity_index_storage_legacy_projections_have_no_bare_sentinel_returns() -> None:
    returns = _function_returns(_source_tree(), _TRACKED_STAGE2089_SYMBOLS)
    assert returns
    bare_sentinel_returns = [row for row in returns if row[2] in {"None", "False", "{}", "0", "1"}]
    assert bare_sentinel_returns == []


def test_stage2100_identity_index_storage_exports_typed_storage_decisions() -> None:
    source_tree = _source_tree()
    function_names = {
        node.name for node in ast.walk(source_tree) if type(node) is ast.FunctionDef
    }
    assert _STAGE2100_TYPED_SYMBOLS <= function_names


def test_stage2100_identity_index_storage_absence_decisions_are_typed_and_legacy_projected(tmp_path: Path) -> None:
    records: list[tuple[str, str]] = []

    queue_decision = identity_index_storage.queue_dir_from_key_decision(
        (), lambda where, exc: records.append((where, type(exc).__name__))
    )
    assert queue_decision.status == "rejected"
    assert queue_decision.reason == "missing_queue_key"
    assert queue_decision.path is None
    assert identity_index_storage.queue_dir_from_key((), lambda where, exc: None) is None
    assert records == [("missing_queue_key", "ValueError")]

    records.clear()
    digest_decision = identity_index_storage.key_digest_decision(
        object(), lambda where, exc: records.append((where, type(exc).__name__))
    )
    assert digest_decision.status == "rejected"
    assert digest_decision.reason == "key_container_rejected"
    assert digest_decision.digest == ""
    assert identity_index_storage.key_digest(object(), lambda where, exc: None) is None
    assert records == [("key_container_rejected", "ValueError")]

    records.clear()
    path_decision = identity_index_storage.index_path_for_key_decision(
        (), lambda where, exc: records.append((where, type(exc).__name__))
    )
    assert path_decision.status == "rejected"
    assert path_decision.reason == "missing_queue_key"
    assert path_decision.path is None
    assert identity_index_storage.index_path_for_key((), lambda where, exc: None) is None
    assert records == [("missing_queue_key", "ValueError")]

    records.clear()
    missing_path = tmp_path / "missing.json"
    read_missing = identity_index_storage.read_index_decision(
        missing_path, lambda where, exc: records.append((where, type(exc).__name__))
    )
    assert read_missing.status == "missing"
    assert read_missing.reason == "identity_index_payload_missing"
    assert read_missing.payload is None
    assert identity_index_storage.read_index(missing_path, lambda where, exc: None) is None
    assert records == []

    records.clear()
    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text("[]", encoding="utf-8")
    read_invalid = identity_index_storage.read_index_decision(
        invalid_path, lambda where, exc: records.append((where, type(exc).__name__))
    )
    assert read_invalid.status == "rejected"
    assert read_invalid.reason == "invalid_payload"
    assert read_invalid.payload is None
    assert identity_index_storage.read_index(invalid_path, lambda where, exc: None) is None
    assert records == [("invalid_payload", "TypeError")]


def test_stage2100_identity_index_storage_rejects_hostile_decisions_without_hooks(tmp_path: Path) -> None:
    HostileValue.reset()
    records: list[tuple[str, str]] = []

    snapshot_decision = identity_index_storage.identity_snapshot_decision(
        HostileValue(),
        lambda where, exc: records.append((where, type(exc).__name__)),
    )
    assert snapshot_decision.status == "rejected"
    assert snapshot_decision.reason == "identities_container_rejected"
    assert snapshot_decision.identities == ()
    assert records == [("identities_container_rejected", "ValueError")]
    assert HostileValue.total_calls() == 0

    HostileValue.reset()
    records.clear()
    item_decision = identity_index_storage.identity_snapshot_decision(
        (HostileValue(),),
        lambda where, exc: records.append((where, type(exc).__name__)),
    )
    assert item_decision.status == "rejected"
    assert item_decision.reason == "queue_identity_index_identity_rejected"
    assert item_decision.identities == ()
    assert records == [("identity_rejected", "ValueError")]
    assert HostileValue.total_calls() == 0

    HostileValue.reset()
    records.clear()
    write_decision = identity_index_storage.write_index_decision(
        tmp_path / "identity.json",
        (HostileValue(),),
        lambda where, exc: records.append((where, type(exc).__name__)),
    )
    assert write_decision.status == "rejected"
    assert write_decision.reason == "queue_identity_index_identity_rejected"
    assert write_decision.written is False
    assert identity_index_storage.write_index(
        tmp_path / "identity.json",
        (HostileValue(),),
        lambda where, exc: None,
    ) is False
    assert records == [("identity_rejected", "ValueError")]
    assert HostileValue.total_calls() == 0
