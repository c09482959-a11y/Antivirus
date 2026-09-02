from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.runtime.execution_memory_capacity import UNBOUNDED_EXECUTION_MEMORY
from Virus_Scan.scheduler.runtime.process_worker_capacity import (
    default_filesystem_queue_workers,
    default_process_scheduler_workers,
    longlived_worker_count,
)


class HookBomb:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _hit(self, _name: str):
        type(self).touched += 1
        raise AssertionError("caller-owned hook executed")

    def __bool__(self):
        return self._hit("__bool__")

    def __float__(self):
        return self._hit("__float__")

    def __format__(self, _spec):
        return self._hit("__format__")

    def __int__(self):
        return self._hit("__int__")

    def __iter__(self):
        return self._hit("__iter__")

    def __repr__(self):
        return self._hit("__repr__")

    def __str__(self):
        return self._hit("__str__")


def test_process_worker_capacity_rejections_record_evidence_without_hooks():
    clear_failure_records()
    HookBomb.reset()
    hostile = HookBomb()
    try:
        assert default_process_scheduler_workers(
            env={"UMIGE_PROCESS_QUEUE_MAX_CHILDREN": hostile},
            cpu_count=hostile,
            recoverable_exceptions=(Exception,),
            memory_snapshot=UNBOUNDED_EXECUTION_MEMORY,
        ) == 4
        assert default_filesystem_queue_workers(cpu_count=hostile, env={}, memory_snapshot=UNBOUNDED_EXECUTION_MEMORY) == 2
        assert longlived_worker_count(
            hostile,
            total_files=hostile,
            env={
                "UMIGE_PROCESS_QUEUE_MAX_CHILDREN": hostile,
                "UMIGE_LONG_LIVED_PROCESS_CAP": hostile,
            },
            memory_snapshot=UNBOUNDED_EXECUTION_MEMORY,
        ) >= 1

        assert HookBomb.touched == 0
        records = [
            record
            for record in failure_snapshot()["records"]
            if record["where"] == "scheduler_process_capacity_integer_rejected"
        ]
        assert records
        assert records[0]["domain"] == "scheduler"
        assert records[0]["error_type"] == "ValueError"
        assert records[0]["suppressed"] is True
        assert records[0]["count"] >= 5
    finally:
        clear_failure_records()


def test_process_worker_capacity_source_has_no_fallback_capacity_route():
    source_path = Path(__file__).resolve().parents[1] / "scheduler" / "runtime" / "process_worker_capacity.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert "fallback" not in source
    assert "return fallback" not in source
    assert "int(cpu)" not in source
    fallback_args = [
        (node.name, arg.arg)
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        for arg in node.args.args + node.args.kwonlyargs
        if arg.arg == "fallback"
    ]
    assert fallback_args == []


def test_stage1937_scheduler_runtime_repaired_snippets_stay_closed():
    root = Path(__file__).resolve().parents[1] / "scheduler" / "runtime"
    forbidden = {
        "queue_filesystem_common.py": (
            'return f"{_UNSUPPORTED_QUEUE_PATH_KEY}:{no_hook_type_name(path)}:{reason}"',
            "os.fspath",
        ),
        "queue_filesystem_dirs.py": (
            'tokens.append(f"{_UNSUPPORTED_STATE_TOKEN}_{index}_{no_hook_type_name(item)}")',
            "os.fspath",
        ),
        "queue_filesystem_identity.py": ("return 1.0", "return None", "fallback="),
        "queue_filesystem_listdir_result.py": ("for key, value in dict.items(materialized_result):", ".setdefault("),
        "queue_filesystem_operations.py": (
            "fallback=",
            'f"delay_reason=',
            '_queue_fs_log_failure(f"',
            "return None",
            "getattr(exc",
        ),
        "queue_filesystem_process.py": ('getattr(subprocess, "CREATE_',),
        "queue_json_cleanup.py": ("int(stride or 1)", "int(limit or 1)", "return 0", "return True", "return False"),
        "queue_json_common.py": ("return False",),
        "queue_json_failures.py": (
            'default=f"unsupported_extra_key_{index}"',
            "def queue_default_failure_info(stage: str, *, exception_type: str =",
            ".items()",
            ".setdefault(",
            "Path(claim_path)",
            "return False",
        ),
        "queue_json_locks.py": ("os.fspath", 'f"unsupported_scheduler_queue_json_path'),
        "queue_json_publication.py": (
            "fallback=",
            "nonce = f",
            "with_name(f",
            "raise OSError(f",
            'log_error(f"queue json',
            'safe_unlink(tmp, log_context="json_replace_tmp_cleanup")',
            'safe_unlink(target, log_context="queue_json_verify_failed")',
            'safe_unlink(target, log_context="queue_json_verify_mismatch")',
            'safe_unlink(tmp, log_context="queue_json_failed_tmp_cleanup")',
            "return False",
        ),
        "queue_json_publication_boundary.py": ("fallback",),
        "queue_json_publication_read.py": ('context=f"', 'record_queue_json_degraded(f"'),
        "queue_json_safety.py": ("value.items()", 'f"unsupported_scheduler_key'),
        "queue_json_schema.py": ("int(default_schema_version or 1)", 'raise ValueError(f"', 'context=f"', "setdefault("),
        "raw_escalation_policy.py": ("fallback", "return True"),
        "raw_worker_capacity.py": ("fallback", "return fallback"),
    }
    violations = []
    for filename, snippets in forbidden.items():
        source = (root / filename).read_text(encoding="utf-8")
        for snippet in snippets:
            if snippet in source:
                violations.append((filename, snippet))
    assert violations == []
