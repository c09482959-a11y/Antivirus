from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import NoReturn
from unittest.mock import patch

import pytest

import Virus_Scan.main as process_entry
import Virus_Scan.persistence as persistence
from Virus_Scan.cli.args import normalize_runtime_args
from Virus_Scan.cli.exit_codes import score_from_result
from Virus_Scan.startup.cli_entry import evaluate
from Virus_Scan.startup.decision import StartupDecision


class HostileValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    @classmethod
    def touch(cls, name: str) -> NoReturn:
        cls.touched += 1
        raise AssertionError("caller-owned hook executed: " + name)

    def __str__(self) -> str:
        type(self).touch("__str__")

    def __repr__(self) -> str:
        type(self).touch("__repr__")

    def __format__(self, _format_spec: str) -> str:
        type(self).touch("__format__")

    def __bool__(self) -> bool:
        type(self).touch("__bool__")

    def __int__(self) -> int:
        type(self).touch("__int__")

    def __float__(self) -> float:
        type(self).touch("__float__")

    def __index__(self) -> int:
        type(self).touch("__index__")

    def __iter__(self):
        type(self).touch("__iter__")

    def __eq__(self, _other: object) -> bool:
        type(self).touch("__eq__")


class HostileOSError(OSError):
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    @classmethod
    def touch(cls, name: str) -> NoReturn:
        cls.touched += 1
        raise AssertionError("exception hook executed: " + name)

    def __str__(self) -> str:
        type(self).touch("__str__")

    def __repr__(self) -> str:
        type(self).touch("__repr__")

    def __format__(self, _format_spec: str) -> str:
        type(self).touch("__format__")


def test_stage2023_cli_normalization_rejects_hostile_partial_output_without_hooks() -> None:
    HostileValue.reset()
    args = SimpleNamespace(partial_output_every=HostileValue())

    assert normalize_runtime_args(args) is args

    assert args.partial_output_every == 10
    assert HostileValue.touched == 0


def test_stage2023_cli_normalization_leaves_unowned_args_container_without_hooks() -> None:
    HostileValue.reset()

    class HostileArgs:
        def __getattribute__(self, name: str) -> object:
            HostileValue.touch("__getattribute__:" + name)

    args = HostileArgs()

    assert normalize_runtime_args(args) is args

    assert HostileValue.touched == 0


def test_stage2023_cli_score_rejects_hostile_declared_scores_without_hooks() -> None:
    HostileValue.reset()

    with pytest.raises(ValueError, match="malformed score field 'score': unsafe_result_score_rejected"):
        score_from_result({"score": HostileValue()})

    assert score_from_result({"layers": {"safe": {"score": 55}}}) == 55.0
    with pytest.raises(ValueError, match="all declared layer scores are malformed"):
        score_from_result({"layers": {"hostile": HostileValue()}})
    assert HostileValue.touched == 0


def test_stage2023_startup_system_exit_code_rejects_hostile_conversion() -> None:
    HostileValue.reset()

    def hostile_parse_args(_tokens: list[str]) -> object:
        raise SystemExit(HostileValue())

    with patch("Virus_Scan.startup.cli_entry.parse_args", hostile_parse_args):
        decision = evaluate(["--help"])

    assert decision.exit_code == 1
    assert HostileValue.touched == 0


def test_stage2023_process_entry_rejects_compiled_and_decision_hooks() -> None:
    HostileValue.reset()

    with patch.object(process_entry.sys, "frozen", HostileValue(), create=True):
        assert process_entry._is_compiled_process() is False

    decision = StartupDecision(kind=HostileValue())  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="unknown_startup_decision:unknown"):
        process_entry._run_decision(decision)
    assert HostileValue.touched == 0


def test_stage2023_persistence_failure_log_uses_exception_type_without_hooks() -> None:
    HostileOSError.reset()
    messages: list[str] = []

    class Runtime:
        parent_cli = True

        def get(self, _name: str, default: object = None) -> object:
            return default

        def has(self, _name: str) -> bool:
            return False

    def fail_flush(*, force: bool = False) -> None:
        raise HostileOSError(HostileValue())

    with patch.object(persistence, "flush_all_persistent_models", fail_flush), patch.object(
        persistence, "log_error", messages.append
    ):
        persistence.flush_persistent_state(Runtime(), SimpleNamespace(strict=False))

    assert len(messages) == 1
    assert "final persistent model flush failed: HostileOSError" in messages[0]
    assert HostileOSError.touched == 0
    assert HostileValue.touched == 0


def test_stage2023_remaining_cli_startup_source_snippets_are_removed() -> None:
    repo = Path(__file__).resolve().parents[2]
    forbidden = {
        "Virus_Scan/cli/args.py": ('n = int(getattr(args, "partial_output_every", 10) or 0)',),
        "Virus_Scan/cli/exit_codes.py": (
            'exc = ValueError(f"malformed score field {key!r}: {score_reason}")',
            "for value in dict.values(layers):",
        ),
        "Virus_Scan/startup/cli_entry.py": ("code = int(exc.code or 0) if isinstance(exc.code, int) else 1",),
        "Virus_Scan/main.py": (
            'if bool(getattr(sys, "frozen", False)):',
            "return False",
            'raise RuntimeError(f"unknown_startup_decision:{decision.kind}")',
            "decision.kind in (",
        ),
        "Virus_Scan/persistence.py": (
            'log_error(f"{failure_tag(PERSISTENCE_FAILURE)} final persistent model flush failed: {exc}")',
        ),
    }
    remaining: list[str] = []
    for relative_path, snippets in forbidden.items():
        text = (repo / relative_path).read_text(encoding="utf-8")
        remaining.extend(relative_path + ": " + snippet for snippet in snippets if snippet in text)
    assert remaining == []
