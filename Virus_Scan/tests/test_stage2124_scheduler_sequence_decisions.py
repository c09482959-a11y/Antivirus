from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.execution.raw_sequence_decision import raw_sequence_decision
from Virus_Scan.scheduler.execution.raw_work_executor import envelope_from_raw_result
from Virus_Scan.scheduler.internal import owned_indexed_sequence
from Virus_Scan.scheduler.internal.owned_indexed_sequence import (
    is_owned_indexed_sequence,
    owned_indexed_sequence_decision,
    owned_indexed_sequence_rejection_reason,
)
from Virus_Scan.scheduler.orchestration import finalization
from Virus_Scan.scheduler.orchestration.finalization import (
    scheduler_results_have_learning_candidate,
    scheduler_results_learning_candidate_decision,
)


class HostileIndexed:
    touched = 0

    def __len__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("len hook executed")

    def __getitem__(self, index):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError(index)


class HostileResults:
    touched = 0

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("iter hook executed")

    def __len__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("len hook executed")

    def __getitem__(self, key):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError(key)

    def values(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("values hook executed")


def _function_returns(module_path: Path, function_name: str) -> list[ast.Return]:
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            return [child for child in ast.walk(node) if isinstance(child, ast.Return)]
    raise AssertionError(function_name)


def test_stage2124_owned_indexed_sequence_decision_is_replayable() -> None:
    exact_list = owned_indexed_sequence_decision([1, 2], writable=True)
    readonly_tuple = owned_indexed_sequence_decision((1, 2), writable=False)
    writable_tuple = owned_indexed_sequence_decision((1, 2), writable=True)

    assert exact_list.is_owned is True
    assert exact_list.accepted_type == "builtin_list"
    assert exact_list.rejection_reason == ""
    assert readonly_tuple.is_owned is True
    assert readonly_tuple.accepted_type == "builtin_tuple_readonly"
    assert writable_tuple.is_owned is False
    assert writable_tuple.rejection_reason == "owned_indexed_sequence_type_rejected"
    assert is_owned_indexed_sequence([1, 2], writable=True) is True
    assert owned_indexed_sequence_rejection_reason([1, 2], writable=True) == ""


def test_stage2124_owned_indexed_sequence_rejects_hostile_without_hooks() -> None:
    HostileIndexed.touched = 0

    decision = owned_indexed_sequence_decision(HostileIndexed(), writable=False)

    assert decision.is_owned is False
    assert decision.rejection_reason == "owned_indexed_sequence_module_rejected"
    assert HostileIndexed.touched == 0


def test_stage2124_raw_sequence_decision_distinguishes_missing_and_rejected() -> None:
    missing = raw_sequence_decision(None)
    rejected_bool = raw_sequence_decision(True)
    accepted = raw_sequence_decision(7)

    assert missing.accepted is False
    assert missing.reason == "raw_sequence_missing"
    assert missing.seq is None
    assert rejected_bool.accepted is False
    assert rejected_bool.reason == "raw_sequence_rejected"
    assert rejected_bool.seq is None
    assert accepted.accepted is True
    assert accepted.reason == "raw_sequence_available"
    assert accepted.seq == 7


def test_stage2124_raw_sequence_public_projection_is_compatible() -> None:
    env = envelope_from_raw_result(
        {"file": "sample.bin", "collector": "raw", "seq": True},
        {"tags": ["raw"]},
    )

    assert env.seq is None


def test_stage2124_learning_candidate_decision_distinguishes_unavailable() -> None:
    HostileResults.touched = 0

    unavailable = scheduler_results_learning_candidate_decision(HostileResults())
    available = scheduler_results_learning_candidate_decision(
        {"sample": {"fast_path": False, "learn_eligible": True}}
    )
    not_found = scheduler_results_learning_candidate_decision(
        {"sample": {"fast_path": True, "learn_eligible": True}}
    )

    assert unavailable.has_candidate is False
    assert unavailable.reason == "scheduler_learning_results_unavailable"
    assert unavailable.inspected_records == 0
    assert HostileResults.touched == 0
    assert available.has_candidate is True
    assert available.reason == "scheduler_learning_candidate_available"
    assert not_found.has_candidate is False
    assert not_found.reason == "scheduler_learning_candidate_not_found"
    assert scheduler_results_have_learning_candidate(
        {"sample": {"fast_path": False, "learn_eligible": True}}
    ) is True


def test_stage2124_public_wrappers_only_project_typed_decisions() -> None:
    owned_source = Path(owned_indexed_sequence.__file__)
    raw_source = Path(finalization.__file__).parents[1] / "execution" / "raw_work_executor.py"
    finalization_source = Path(finalization.__file__)

    assert "return \"\"" not in owned_source.read_text(encoding="utf-8")
    for ret in _function_returns(raw_source, "_raw_seq"):
        assert not (isinstance(ret.value, ast.Constant) and ret.value.value is None)
    for ret in _function_returns(finalization_source, "scheduler_results_have_learning_candidate"):
        assert not (isinstance(ret.value, ast.Constant) and type(ret.value.value) is bool)
