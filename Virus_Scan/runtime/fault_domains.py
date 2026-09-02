"""Explicit fault-domain containment helpers.

Use these wrappers around extraction/decompiler/reporting/persistence/correlation
boundaries so one subsystem failure is converted into local tags/diagnostics
instead of poisoning broader runtime state.
"""
from __future__ import annotations

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator
from Virus_Scan.runtime.structured_failures import record_failure
from Virus_Scan.runtime.immutable_core import freeze_runtime_value, materialize_runtime_value
from Virus_Scan.runtime.governance_inputs import runtime_text


@dataclass(frozen=True)
class FailureDomain:
    name: str
    tag: str

    def __post_init__(self) -> None:
        if type(self) is not FailureDomain:
            exception_message = "failure domain owner rejected"
            raise TypeError(exception_message)
        name, name_issues = runtime_text(
            self.name,
            field_name="failure_domain_name",
            default="input_rejected",
        )
        tag, tag_issues = runtime_text(
            self.tag,
            field_name="failure_domain_tag",
            default="failure_domain_input_rejected",
        )
        if name_issues or tag_issues:
            exception_message = "failure domain fields rejected"
            raise ValueError(exception_message)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "tag", tag)


EXTRACTION_FAILURE = FailureDomain("extraction", "failure_domain_extraction")
DECOMPILER_FAILURE = FailureDomain("decompiler", "failure_domain_decompiler")
REPORTING_FAILURE = FailureDomain("reporting", "failure_domain_reporting")
CORRELATION_FAILURE = FailureDomain("correlation", "failure_domain_correlation")
PERSISTENCE_FAILURE = FailureDomain("persistence", "failure_domain_persistence")
RUNTIME_FAILURE = FailureDomain("runtime", "failure_domain_runtime")


def _failure_domain_tag(normalized: str) -> str:
    return "failure_domain_" + (normalized or "runtime")


def failure_tag(domain: FailureDomain | str) -> str:
    if type(domain) is FailureDomain:
        return domain.tag
    text, issues = runtime_text(
        domain,
        field_name="failure_domain_value",
        default="input_rejected",
    )
    if issues:
        return "failure_domain_input_rejected"
    normalized = text.strip().lower().replace(" ", "_")
    return _failure_domain_tag(normalized)


def append_failure_domain(tags: list[str], domain: FailureDomain | str) -> list[str]:
    tag = failure_tag(domain)
    if tag not in tags:
        tags.append(tag)
    return tags


@dataclass(frozen=True)
class FaultResult:
    ok: bool
    value: object = None
    error: Exception | None = None
    domain: FailureDomain | str = RUNTIME_FAILURE

    def __post_init__(self) -> None:
        if type(self) is not FaultResult:
            exception_message = "fault result owner rejected"
            raise TypeError(exception_message)
        object.__setattr__(self, "value", freeze_runtime_value(self.value))

    def materialized_value(self) -> object:
        return materialize_runtime_value(self.value)

    @property
    def tag(self) -> str:
        return failure_tag(self.domain)


def contain_fault(domain: FailureDomain | str, func: Callable[..., object], *args: object, default: object = None, logger: Callable[[str], object] | None = None, **kwargs: object) -> FaultResult:
    try:
        return FaultResult(ok=True, value=func(*args, **kwargs), error=None, domain=domain)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_failure(failure_tag(domain), "contain_fault", exc, logger=logger)
        return FaultResult(ok=False, value=default, error=exc, domain=domain)


@contextmanager
def fault_boundary(domain: FailureDomain | str, tags: list[str] | None = None, *, logger: Callable[[str], object] | None = None) -> Iterator[None]:
    try:
        yield
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        if tags is not None:
            append_failure_domain(tags, domain)
        record_failure(failure_tag(domain), "fault_boundary", exc, logger=logger)
        raise


__all__ = (
    "CORRELATION_FAILURE",
    "DECOMPILER_FAILURE",
    "EXTRACTION_FAILURE",
    "PERSISTENCE_FAILURE",
    "REPORTING_FAILURE",
    "RUNTIME_FAILURE",
    "FailureDomain",
    "FaultResult",
    "append_failure_domain",
    "contain_fault",
    "failure_tag",
    "fault_boundary",
)
