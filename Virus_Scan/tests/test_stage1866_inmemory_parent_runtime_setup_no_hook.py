"""Stage1866 regression tests for in-memory parent runtime setup no-hook boundaries."""
from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.scheduler.orchestration import inmemory_parent_runtime_setup as runtime_setup


class HostileProcessCount:
    def __bool__(self):  # pragma: no cover - must not be called
        raise AssertionError("process count truthiness hook executed")

    def __int__(self):  # pragma: no cover - must not be called
        raise AssertionError("process count int hook executed")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, 1),
        (0, 1),
        (-7, 1),
        (3, 3),
        (3.0, 3),
        (2.5, 1),
        (" 4 ", 4),
        ("", 1),
        ("bad", 1),
        (HostileProcessCount(), 1),
    ],
)
def test_stage1866_process_count_parser_rejects_hostile_hooks(value, expected):
    assert runtime_setup._positive_process_count(value) == expected


def test_stage1866_inmemory_parent_runtime_setup_source_has_no_hookable_logging_materialization():
    source = Path(runtime_setup.__file__).read_text(encoding="utf-8")
    assert "int(request.process_count or 1)" not in source
    assert "dict(runtime_snapshot.stage_limits)}" not in source
    assert 'f"bulk scan scheduler=inmemory-longlived-threaded' not in source
    assert "f\"threads_per_process=" not in source
    assert "f\"stage_limits=" not in source
