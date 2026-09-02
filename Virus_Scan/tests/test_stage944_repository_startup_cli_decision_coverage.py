from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from Virus_Scan.startup.cli_entry import evaluate
from Virus_Scan.startup.decision import RuntimeRequest, StartupDecision, StartupDecisionKind


def test_stage944_startup_help_version_and_parse_errors_are_classified_without_runtime_request(capsys: pytest.CaptureFixture[str]) -> None:
    help_decision = evaluate(["--help"])
    assert help_decision.kind is StartupDecisionKind.HELP
    assert help_decision.exit_code == 0
    assert help_decision.runtime_request is None

    version_decision = evaluate(["--version"])
    assert version_decision.kind is StartupDecisionKind.VERSION
    assert version_decision.exit_code == 0
    assert version_decision.runtime_request is None

    error_decision = evaluate([])
    assert error_decision.kind is StartupDecisionKind.ERROR
    assert error_decision.exit_code == 2
    assert error_decision.runtime_request is None

    captured = capsys.readouterr()
    assert "UMIGE" in captured.out
    assert "required: --dir" in captured.err


def test_stage944_startup_scan_decision_preserves_immutable_runtime_request_argv() -> None:
    decision = evaluate(["--dir", "sample", "--engine", "unity", "--scheduler", "serial"])

    assert decision.kind is StartupDecisionKind.SCAN
    assert decision.exit_code == 0
    assert decision.runtime_request is not None
    assert decision.runtime_request.argv == ("--dir", "sample", "--engine", "unity", "--scheduler", "serial")
    assert decision.runtime_request.args.dir == "sample"
    assert decision.runtime_request.args.engine == "unity"
    assert decision.runtime_request.args.scheduler == "serial"

    with pytest.raises(FrozenInstanceError):
        decision.runtime_request.argv = ("mutated",)  # type: ignore[misc]


def test_stage944_startup_decision_factories_preserve_kind_and_immutability() -> None:
    request = RuntimeRequest(args={"dir": "target"}, argv=("--dir", "target"))

    assert StartupDecision.help().kind is StartupDecisionKind.HELP
    assert StartupDecision.version().kind is StartupDecisionKind.VERSION
    assert StartupDecision.error(7).exit_code == 7

    scan = StartupDecision.scan(request)
    assert scan.kind is StartupDecisionKind.SCAN
    assert scan.runtime_request is request

    with pytest.raises(FrozenInstanceError):
        scan.kind = StartupDecisionKind.ERROR  # type: ignore[misc]
