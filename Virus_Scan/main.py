"""UMIGE startup-only process entrypoint.

Importing this module remains startup safe for normal startup/help/version
mode. It owns startup decision evaluation and explicit process handoff for scan
mode. Scan execution is owned by ``Virus_Scan.runtime_main`` in a runtime child
process so the startup/help path never imports scanner, YARA, reporting,
scheduler, detection, model, or runtime lifecycle modules.
"""
from __future__ import annotations

import subprocess
import sys
from typing import Optional, Sequence

from Virus_Scan.contracts.no_hook_materialization import no_hook_text

_RUNTIME_CHILD_ARG = "--umige-runtime-child"
from Virus_Scan.startup.cli_entry import evaluate
from Virus_Scan.startup.decision import RuntimeRequest, StartupDecision, StartupDecisionKind


def _runtime_argv(request: RuntimeRequest) -> tuple[str, ...]:
    if not isinstance(request, RuntimeRequest):
        raise TypeError("process_handoff_requires_RuntimeRequest")
    if request.argv is None:
        return ()
    return tuple(str(item) for item in request.argv)


def _is_compiled_process() -> bool:
    if vars(sys).get("frozen") is True:
        return True
    return "__compiled__" in globals()


def _runtime_process_command_for_mode(runtime_argv: tuple[str, ...], *, compiled_process: bool) -> tuple[str, ...]:
    if not isinstance(compiled_process, bool):
        raise TypeError("compiled_process_must_be_bool")
    if compiled_process:
        return (sys.executable, _RUNTIME_CHILD_ARG, *runtime_argv)
    return (sys.executable, "-m", "Virus_Scan.runtime_main", *runtime_argv)


def _runtime_process_command(runtime_argv: tuple[str, ...]) -> tuple[str, ...]:
    return _runtime_process_command_for_mode(runtime_argv, compiled_process=_is_compiled_process())


def _run_runtime_process(request: RuntimeRequest) -> int:
    runtime_argv = _runtime_argv(request)
    completed = subprocess.run(_runtime_process_command(runtime_argv), check=False)
    return int(completed.returncode)


def _run_decision(decision: StartupDecision) -> int:
    if not isinstance(decision, StartupDecision):
        raise TypeError("process_entry_requires_StartupDecision")
    kind = decision.kind
    if kind is StartupDecisionKind.HELP or kind is StartupDecisionKind.VERSION or kind is StartupDecisionKind.ERROR:
        return int(decision.exit_code)
    if kind is StartupDecisionKind.SCAN:
        if decision.runtime_request is None:
            raise RuntimeError("scan_decision_missing_runtime_request")
        return _run_runtime_process(decision.runtime_request)
    kind_text, kind_reason = no_hook_text(
        kind,
        missing_reason="missing_startup_decision_kind",
        unsupported_reason="unsafe_startup_decision_kind_rejected",
    )
    raise RuntimeError("unknown_startup_decision:" + ("unknown" if kind_reason else kind_text))


def main(argv: Optional[Sequence[str]] = None) -> int:
    tokens = tuple(sys.argv[1:] if argv is None else argv)
    decision = evaluate(tokens)
    return _run_decision(decision)


if __name__ == "__main__":
    raise SystemExit(main())
