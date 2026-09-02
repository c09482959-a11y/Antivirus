"""Scanner collector/analyzer/governance helpers.

This gives large scanner files a common execution contract without changing
existing detector behavior: collectors gather bytes/text, analyzers evaluate
heuristics, and governance enforces budgets + records failures.
"""
from __future__ import annotations
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from dataclasses import dataclass, field
from typing import Callable

_PROGRAMMER_ERROR_TYPES = (AssertionError, AttributeError, ImportError, ModuleNotFoundError, NameError, TypeError)

class ScannerContractViolation(RuntimeError):
    """Raised when scanner code violates its interface contract.

    Hostile or malformed input should be degraded into structured scanner
    failure tags. Programmer/interface errors must not be hidden behind
    false-clean results because that masks refactor drift.
    """

def _scanner_text(value: object, *, default: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="scanner_text_missing",
        unsupported_reason="scanner_text_unsupported",
    )
    if reason:
        return default
    return text


def _scanner_exception_message(exc: BaseException | str) -> str:
    if type(exc) is str:
        return str.__str__(exc)
    if isinstance(exc, BaseException) and type(exc) in (*_PROGRAMMER_ERROR_TYPES, EOFError, OSError, RuntimeError, ValueError, UnicodeError):
        try:
            args = BaseException.__getattribute__(exc, "args")
        except (AttributeError, TypeError, RuntimeError, ValueError, UnicodeError):
            return no_hook_type_name(exc)
        if type(args) is tuple and len(args) == 1:
            return _scanner_text(tuple.__getitem__(args, 0), default=no_hook_type_name(exc))
    return no_hook_type_name(exc)


def _append_marker(tags: list[str], marker: str) -> None:
    for item in tags:
        if type(item) is str and item == marker:
            return
    tags.append(marker)


def _extend_exact_tags(tags: list[str], values: object) -> None:
    if type(values) not in (list, tuple, set, frozenset):
        return
    for value in values:
        tag = _scanner_text(value, default="").strip()
        if tag:
            _append_marker(tags, tag)


def is_programmer_error(exc: BaseException) -> bool:
    return isinstance(exc, _PROGRAMMER_ERROR_TYPES)

def scanner_failure_tags(where: str, exc: BaseException | str, base_tags: object=None) -> list[str]:
    tags: list[str] = []
    _extend_exact_tags(tags, base_tags)
    failure_site = _scanner_text(where, default="scanner_failure") or "scanner_failure"
    tag = record_suppressed_failure(failure_site, exc, domain="scanner", tags=tags)
    for marker in ("scanner_failure", "scanner_degraded", "scan_incomplete"):
        _append_marker(tags, marker)
    _append_marker(tags, tag)
    return tags

@dataclass
class ScannerContext:
    path: str | None = None
    engine: str | None = None
    source: str | None = None
    tags: list[str] = field(default_factory=list)
    telemetry: object = None
    budgets: dict[str, int] = field(default_factory=dict)

    def add_tags(self, values: object) -> None:
        _extend_exact_tags(self.tags, values)

    def fail(self, where: str, exc: BaseException | str, domain: str | None = None) -> str:
        failure_site = _scanner_text(where, default="scanner_failure") or "scanner_failure"
        failure_domain = _scanner_text(domain, default="scanner") if domain is not None else "scanner"
        return record_suppressed_failure(failure_site, exc, domain=failure_domain, tags=self.tags, telemetry=self.telemetry)


def run_collector(ctx: ScannerContext, where: str, fn: Callable[..., object], *args: object, default: object = None, **kwargs: object) -> object:
    try:
        return fn(*args, **kwargs)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        if is_programmer_error(exc):
            site = _scanner_text(where, default="collector") or "collector"
            message = _scanner_exception_message(exc)
            raise ScannerContractViolation("collector contract violation at " + site + ": " + message) from exc
        ctx.fail(where, exc, "parse")
        return default


def _non_materializable_analyzer_result(ctx: ScannerContext, where: str, result: object) -> dict:
    tag = ctx.fail(where, "scanner_analyzer_non_materializable_result", "scanner")
    return {
        "tags": ["scanner_failure", "scanner_degraded", "scan_incomplete", tag],
        "error": "scanner_analyzer_non_materializable_result",
        "degraded": True,
        "scanner_evidence_unavailable_reason": "non_materializable_analyzer_result",
        "result_type": no_hook_type_name(result),
    }


def run_analyzer(ctx: ScannerContext, where: str, fn: Callable[..., dict], *args: object, **kwargs: object) -> dict:
    try:
        result = fn(*args, **kwargs)
        if result is None:
            tag = ctx.fail(where, "scanner_analyzer_returned_none", "scanner")
            return {
                "tags": ["scanner_failure", "scanner_degraded", "scan_incomplete", tag],
                "error": "scanner_analyzer_returned_none",
                "degraded": True,
                "scanner_evidence_unavailable_reason": "scanner_analyzer_returned_none",
            }
        if type(result) is not dict:
            return _non_materializable_analyzer_result(ctx, where, result)
        ctx.add_tags(dict.get(result, "tags"))
    except (*RECOVERABLE_RUNTIME_ERRORS, EOFError) as exc:
        if is_programmer_error(exc):
            site = _scanner_text(where, default="analyzer") or "analyzer"
            message = _scanner_exception_message(exc)
            raise ScannerContractViolation("analyzer contract violation at " + site + ": " + message) from exc
        tag = ctx.fail(where, exc, "scanner")
        return {"tags": ["scanner_failure", "scanner_degraded", "scan_incomplete", tag], "error": _scanner_exception_message(exc), "degraded": True}
    else:
        return result

__all__=("ScannerContext", "ScannerContractViolation", "is_programmer_error", "run_analyzer", "run_collector", "scanner_failure_tags")
