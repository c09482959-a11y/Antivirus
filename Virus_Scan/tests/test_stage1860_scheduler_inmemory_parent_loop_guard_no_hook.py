from Virus_Scan.tests.support.static_inventory import read_python_file


"""Stage1860 in-memory parent loop/guard no-hook regressions."""
from pathlib import Path

from Virus_Scan.scheduler.orchestration.inmemory_parent_loop import (
    _owned_failed_count,
    empty_longlived_parent_result_decision,
    owned_failed_count_decision,
)
from Virus_Scan.scheduler.orchestration.inmemory_parent_loop_guard import _completed_count


class HostileFailedCollection:
    touched = False

    def __len__(self):  # pragma: no cover - must not be invoked
        type(self).touched = True
        raise AssertionError("__len__ hook executed")

    def __bool__(self):  # pragma: no cover - must not be invoked
        type(self).touched = True
        raise AssertionError("__bool__ hook executed")

    def __iter__(self):  # pragma: no cover - must not be invoked
        type(self).touched = True
        raise AssertionError("__iter__ hook executed")

    def __repr__(self):  # pragma: no cover - must not be invoked
        type(self).touched = True
        raise AssertionError("__repr__ hook executed")

    def __format__(self, format_spec):  # pragma: no cover - must not be invoked
        type(self).touched = True
        raise AssertionError("__format__ hook executed")


class HostileCompletedValue:
    touched = False

    def __int__(self):  # pragma: no cover - must not be invoked
        type(self).touched = True
        raise AssertionError("__int__ hook executed")

    def __bool__(self):  # pragma: no cover - must not be invoked
        type(self).touched = True
        raise AssertionError("__bool__ hook executed")

    def __str__(self):  # pragma: no cover - must not be invoked
        type(self).touched = True
        raise AssertionError("__str__ hook executed")

    def __repr__(self):  # pragma: no cover - must not be invoked
        type(self).touched = True
        raise AssertionError("__repr__ hook executed")

    def __format__(self, format_spec):  # pragma: no cover - must not be invoked
        type(self).touched = True
        raise AssertionError("__format__ hook executed")


def test_failed_count_rejects_unknown_failed_collection_without_hooks():
    HostileFailedCollection.touched = False

    assert _owned_failed_count(HostileFailedCollection()) == 0
    assert HostileFailedCollection.touched is False


def test_failed_count_accepts_exact_builtin_containers_only():
    assert _owned_failed_count({"a"}) == 1
    assert _owned_failed_count(frozenset({"a", "b"})) == 2
    assert _owned_failed_count({"a": 1}) == 1
    assert _owned_failed_count([1, 2, 3]) == 3
    assert _owned_failed_count((1, 2)) == 2


def test_completed_count_rejects_unknown_completed_value_without_hooks():
    HostileCompletedValue.touched = False

    assert _completed_count(HostileCompletedValue()) == 0
    assert HostileCompletedValue.touched is False


def test_completed_count_uses_no_hook_integer_boundary():
    assert _completed_count("3") == 3
    assert _completed_count(4) == 4
    assert _completed_count(-5) == 0
    assert _completed_count(True) == 0


def test_removed_parent_loop_fstring_failed_count_route_stays_removed():
    source = read_python_file(Path("Virus_Scan/scheduler/orchestration/inmemory_parent_loop.py"))

    assert "f'in-memory scheduler failed jobs:" not in source
    assert 'f"in-memory scheduler failed jobs:' not in source
    assert "len(setup.failed)" not in source


def test_removed_parent_loop_completed_int_or_route_stays_removed():
    source = read_python_file(Path("Virus_Scan/scheduler/orchestration/inmemory_parent_loop_guard.py"))

    assert "int(setup.recovery.completed" not in source
    assert "setup.recovery.completed or" not in source


def test_stage2187_failed_count_decision_records_rejected_collection_without_hooks():
    HostileFailedCollection.touched = False

    decision = owned_failed_count_decision(HostileFailedCollection())

    assert decision.count == 0
    assert decision.accepted is False
    assert decision.reason == "owned_failed_collection_rejected"
    assert decision.replayable is True
    assert decision.as_count() == 0
    assert HostileFailedCollection.touched is False


def test_stage2187_empty_longlived_parent_result_is_replayable_decision():
    decision = empty_longlived_parent_result_decision()

    assert decision.results == {}
    assert decision.accepted is False
    assert decision.reason == "longlived_parent_no_files"
    assert decision.replayable is True
    assert decision.as_results() == {}
