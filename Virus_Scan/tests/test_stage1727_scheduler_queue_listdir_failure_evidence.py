from Virus_Scan.tests.support.static_inventory import parse_python_file, python_files_under, read_python_file

import ast
from pathlib import Path


import pytest

from Virus_Scan.scheduler.runtime import queue_filesystem_operations as queue_fs_ops
from Virus_Scan.scheduler.queue.process_queue_terminal_counts import terminal_queue_counts
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import QueueListdirFailure

_SCHEDULER_ROOT = (Path(__file__).resolve().parents[2] / "Virus_Scan" / "scheduler").resolve()


def _scheduler_source_files() -> tuple[Path, ...]:
    return python_files_under("Virus_Scan/scheduler")


def _scheduler_tree(path: Path) -> ast.AST:
    return parse_python_file(path)


class HostilePath:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("path truthiness must not execute")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("path str must not execute")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("path repr must not execute")

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("path fspath must not execute")


def test_stage1727_safe_queue_listdir_rejects_hostile_path_without_hooks():
    HostilePath.touched = 0

    result = queue_fs_ops.safe_queue_listdir(HostilePath())

    assert HostilePath.touched == 0
    assert isinstance(result, QueueListdirFailure)
    assert result != []
    with pytest.raises(TypeError):
        list(result)
    evidence = result.as_dict()
    assert evidence["queue_listdir_failed"] is True
    assert evidence["scheduler_filesystem_unavailable"] is True
    assert evidence["reason"] == "scheduler_path_rejected"
    assert evidence["path_evidence"]["path_reason"] == "scheduler_path_rejected"
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_record"] is True


def test_stage1727_safe_queue_listdir_filesystem_failure_returns_evidence(tmp_path):
    file_path = tmp_path / "not_a_directory"
    file_path.write_text("occupied", encoding="utf-8")

    result = queue_fs_ops.safe_queue_listdir(file_path)

    assert isinstance(result, QueueListdirFailure)
    assert result != []
    with pytest.raises(TypeError):
        list(result)
    evidence = result.as_dict()
    assert evidence["reason"] == "queue_listdir_directory_create_failed"
    assert evidence["error_evidence"]["error_type"] == "FileExistsError"
    assert "FileExistsError" in evidence["error_evidence"]["error_detail"]
    assert "caller hooks" in evidence["error_evidence"]["error_detail"]


def test_stage1727_safe_queue_listdir_success_preserves_directory_names(tmp_path):
    (tmp_path / "b.job.json").write_text("{}", encoding="utf-8")
    (tmp_path / "a.job.json").write_text("{}", encoding="utf-8")

    result = queue_fs_ops.safe_queue_listdir(tmp_path)

    assert sorted(result) == ["a.job.json", "b.job.json"]


def test_stage1727_terminal_queue_counts_propagate_listdir_failure(tmp_path):
    pending = tmp_path / "pending"
    active = tmp_path / "active"
    failed = tmp_path / "failed"
    for directory in (pending, active, failed):
        directory.mkdir()
    failure = queue_fs_ops.safe_queue_listdir(HostilePath())

    with pytest.raises(QueueListdirFailure):
        terminal_queue_counts(
            pending,
            active,
            failed,
            safe_listdir=lambda _directory: failure,
            is_job_name=lambda name: name.endswith(".json"),
        )


def test_stage1727_production_listdir_consumers_use_the_canonical_failure_gate():
    offenders: list[str] = []
    for path in _scheduler_source_files():
        if path.name == "queue_filesystem_operations.py":
            continue
        source = read_python_file(path)
        if (
            "safe_queue_listdir" not in source
            and "_safe_queue_listdir" not in source
            and "safe_listdir" not in source
        ):
            continue
        tree = _scheduler_tree(path)
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                called = node.func.id
            elif isinstance(node.func, ast.Attribute):
                called = node.func.attr
            else:
                continue
            if called not in {"safe_queue_listdir", "_safe_queue_listdir", "safe_listdir"}:
                continue
            parent = parents.get(node)
            if not (
                isinstance(parent, ast.Call)
                and isinstance(parent.func, ast.Name)
                and parent.func.id == "queue_listdir_names"
            ):
                offenders.append(f"{path.relative_to(_SCHEDULER_ROOT)}:{node.lineno}:{called}")

    assert offenders == []
