"""Startup-only CLI decision entrypoint for UMIGE.

This module owns argv normalization, CLI parser execution, help/version/error
classification, and immutable scan-request construction. It imports only CLI
parser code and startup decision types. Scan runtime ownership is represented as
data and handed to the top-level process entrypoint.
"""
from __future__ import annotations

import sys
from typing import Optional, Sequence, Tuple

from Virus_Scan.cli.args import parse_args
from Virus_Scan.startup.decision import RuntimeRequest, StartupDecision


def _argv_tuple(argv: Optional[Sequence[str]]) -> Tuple[str, ...] | None:
    if argv is None:
        return None
    return tuple(str(item) for item in argv)


def _tokens(argv: Optional[Sequence[str]]) -> tuple[str, ...]:
    return tuple(sys.argv[1:] if argv is None else argv)


def evaluate(argv: Optional[Sequence[str]] = None) -> StartupDecision:
    """Parse startup arguments and classify the command without runtime imports."""
    tokens = _tokens(argv)
    wants_help = any(token in ("-h", "--help") for token in tokens)
    wants_version = any(token == "--version" for token in tokens)
    try:
        args = parse_args(list(tokens))
    except SystemExit as exc:
        code = exc.code if type(exc.code) is int else 1
        if wants_help and code == 0:
            return StartupDecision.help(code)
        if wants_version and code == 0:
            return StartupDecision.version(code)
        return StartupDecision.error(code)
    return StartupDecision.scan(RuntimeRequest(args=args, argv=_argv_tuple(tokens)))


__all__ = ("evaluate",)
