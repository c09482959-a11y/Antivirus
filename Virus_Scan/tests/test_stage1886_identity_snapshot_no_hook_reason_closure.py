from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan.scheduler.queue.identity_snapshot import QueueJobIdentitySnapshot


class HostileValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("str")

    def __repr__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("repr")

    def __format__(self, spec):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("format")

    def __bool__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("bool")

    def __iter__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("iter")


class HostileMapping:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __iter__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("iter")

    def items(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("items")

    def __bool__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("bool")

    def __repr__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("repr")


def _identity_snapshot_tree() -> ast.Module:
    root = Path(__file__).resolve().parents[2]
    source = root / "Virus_Scan" / "scheduler" / "queue" / "identity_snapshot.py"
    return parse_python_file(source)


def test_stage1886_identity_snapshot_rejects_hostile_source_name_without_hooks() -> None:
    HostileValue.reset()

    snapshot = QueueJobIdentitySnapshot.from_job(
        {"job_type": "raw_stage", "file_id": "abc", "collector": "strings", "seq": "2"},
        HostileValue(),
    )

    assert snapshot.source_name == "unknown"
    assert snapshot.rejections == ("process_queue_identity_source_name_rejected",)
    assert HostileValue.touched == 0


def test_stage1886_identity_snapshot_rejects_hostile_mapping_without_hooks() -> None:
    HostileMapping.reset()

    snapshot = QueueJobIdentitySnapshot.from_job(HostileMapping(), "job.json")

    assert snapshot.job_type == "file"
    assert snapshot.source_name == "job.json"
    assert snapshot.rejections == ()
    assert HostileMapping.touched == 0


def test_stage1886_identity_snapshot_rejects_hostile_file_values_without_hooks() -> None:
    HostileValue.reset()

    snapshot = QueueJobIdentitySnapshot.from_job({"file": HostileValue()}, "job.json")

    assert snapshot.file == ""
    assert snapshot.file_id == ""
    assert snapshot.rejections == (
        "process_queue_identity_file_rejected",
        "process_queue_identity_file_id_rejected",
    )
    assert HostileValue.touched == 0


def test_stage1886_identity_snapshot_has_no_fstring_materialization_or_items_loop() -> None:
    tree = _identity_snapshot_tree()
    joined_strings = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)]
    item_calls = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "items"
    ]
    assert joined_strings == []
    assert item_calls == []
