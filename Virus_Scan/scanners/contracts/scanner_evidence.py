"""Immutable scanner failure evidence records.

Scanner functions still return their existing tag/result shapes, but recoverable
failures that affect those results can now carry a JSON-safe evidence record and
canonical degraded tags without depending on mutable recorder state.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from Virus_Scan.contracts.no_hook_materialization import (
    exact_bool_or_none,
    no_hook_exact_nonnegative_int,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.contracts.result_record import degraded_scan_integrity, scanner_degraded_tags

ScannerContractValue = object




def scanner_contract_text(
    value: ScannerContractValue,
    *,
    replacement: str = "",
    missing_reason: str = "missing_scanner_contract_text",
    unsupported_reason: str = "unsafe_scanner_contract_text_rejected",
) -> str:
    """Return scanner-owned text without invoking caller-owned hooks."""
    text, reason = no_hook_text(value, missing_reason=missing_reason, unsupported_reason=unsupported_reason)
    if reason:
        return str.__str__(replacement) if type(replacement) is str else ""
    return text


def scanner_contract_lower_token(value: ScannerContractValue, *, replacement: str = "scanner") -> str:
    text = scanner_contract_text(value, replacement=replacement).strip().lower()
    return text or str.__str__(replacement)


def scanner_contract_nonnegative_int(value: ScannerContractValue, *, replacement: int = 0) -> int:
    number, reason = no_hook_exact_nonnegative_int(value, default=replacement)
    return replacement if reason else number


def scanner_contract_bool(value: ScannerContractValue, *, replacement: bool = False) -> bool:
    exact = exact_bool_or_none(value)
    if exact is not None:
        return exact
    return replacement if type(replacement) is bool else False


def scanner_contract_bytes(value: ScannerContractValue) -> bytes:
    if type(value) is bytes:
        return bytes(value)
    if type(value) is bytearray:
        return bytes(value)
    return b""


def scanner_contract_error_message(error: ScannerContractValue) -> str:
    if type(error) is str:
        return str.__str__(error)[:500]
    if isinstance(error, BaseException):
        return scanner_contract_join("exception:", no_hook_type_name(error))[:500]
    return scanner_contract_text(error, replacement=scanner_contract_join("unsupported_error:", no_hook_type_name(error)))[:500]


def scanner_contract_join(*parts: str) -> str:
    out = ""
    for part in parts:
        if type(part) is str:
            out = str.__add__(out, str.__str__(part))
    return out

from Virus_Scan.scanners.contracts.scanner_evidence_freeze_support import (
    freeze_scanner_contract_value,
    freeze_scanner_evidence_records,
    materialize_scanner_contract_value,
    materialize_scanner_evidence_records,
)


@dataclass(frozen=True, slots=True)
class ScannerFailureEvidence:
    scanner_name: str
    input_path: str
    scanner_stage: str
    state: str
    error_category: str
    error_source: str
    exception_type: str
    message: str
    policy_config_source: str = "module_default"
    file_type: str = ""
    decode_depth: int | None = None
    archive_depth: int | None = None
    truncation_status: str = ""
    fatal: bool = False
    final_json_must_record: bool = True

    @classmethod
    def from_exception(
        cls,
        *,
        scanner_name: str,
        stage: str,
        error: BaseException | str,
        input_path: ScannerContractValue = "",
        state: str = "degraded",
        error_category: str = "recoverable_scanner_failure",
        error_source: str | None = None,
        policy_config_source: str = "module_default",
        file_type: str = "",
        decode_depth: int | None = None,
        archive_depth: int | None = None,
        truncation_status: str = "",
        fatal: bool = False,
    ) -> "ScannerFailureEvidence":
        return cls(
            scanner_name=scanner_contract_text(scanner_name, replacement="scanner"),
            input_path=scanner_contract_text(input_path, replacement=""),
            scanner_stage=scanner_contract_text(stage, replacement="unknown"),
            state=scanner_contract_text(state, replacement="degraded"),
            error_category=scanner_contract_text(error_category, replacement="recoverable_scanner_failure"),
            error_source=scanner_contract_text(error_source, replacement=scanner_contract_text(stage, replacement="unknown")),
            exception_type=no_hook_type_name(error) if isinstance(error, BaseException) else "Failure",
            message=scanner_contract_error_message(error),
            policy_config_source=scanner_contract_text(policy_config_source, replacement="module_default"),
            file_type=scanner_contract_text(file_type, replacement=""),
            decode_depth=decode_depth,
            archive_depth=archive_depth,
            truncation_status=scanner_contract_text(truncation_status, replacement=""),
            fatal=scanner_contract_bool(fatal, replacement=False),
        )

    def to_record(self) -> dict[str, ScannerContractValue]:
        return asdict(self)

    def to_scan_integrity(self) -> dict[str, ScannerContractValue]:
        return degraded_scan_integrity(
            self.message,
            scanner=self.scanner_name,
            scanner_stage=self.scanner_stage,
            scanner_failure_evidence=self.to_record(),
            final_json_must_record=self.final_json_must_record,
        )


def scanner_failure_evidence_record(
    scanner_name: str,
    stage: str,
    error: BaseException | str,
    *,
    input_path: ScannerContractValue = "",
    state: str = "degraded",
    error_category: str = "recoverable_scanner_failure",
    error_source: str | None = None,
    policy_config_source: str = "module_default",
    file_type: str = "",
    decode_depth: int | None = None,
    archive_depth: int | None = None,
    truncation_status: str = "",
    fatal: bool = False,
) -> dict[str, ScannerContractValue]:
    evidence = ScannerFailureEvidence.from_exception(
        scanner_name=scanner_name,
        stage=stage,
        error=error,
        input_path=input_path,
        state=state,
        error_category=error_category,
        error_source=error_source,
        policy_config_source=policy_config_source,
        file_type=file_type,
        decode_depth=decode_depth,
        archive_depth=archive_depth,
        truncation_status=truncation_status,
        fatal=fatal,
    )
    return evidence.to_record()


def scanner_failure_evidence_tags(
    scanner_name: str,
    stage: str,
    error: BaseException | str,
    base_tags: ScannerContractValue = None,
    *,
    input_path: ScannerContractValue = "",
    state: str = "degraded",
    error_category: str = "recoverable_scanner_failure",
    error_source: str | None = None,
    file_type: str = "",
) -> list[str]:
    del error, input_path, state, error_category, error_source, file_type
    stage_tag = scanner_contract_join(scanner_contract_lower_token(stage, replacement="scanner"), "_scan_error")
    tags = scanner_degraded_tags(base_tags if base_tags is not None else [], stage_tag, "scanner_failure_evidence_recorded")
    evidence_tag = scanner_contract_join(
        "scanner_failure_evidence:",
        scanner_contract_lower_token(scanner_name, replacement="scanner"),
        ":",
        scanner_contract_lower_token(stage, replacement="unknown"),
    )
    if evidence_tag in tags:
        return tags
    return [*tags, evidence_tag]


__all__ = (
    "ScannerFailureEvidence",
    "freeze_scanner_contract_value",
    "freeze_scanner_evidence_records",
    "materialize_scanner_contract_value",
    "materialize_scanner_evidence_records",
    "scanner_contract_bool",
    "scanner_contract_bytes",
    "scanner_contract_error_message",
    "scanner_contract_join",
    "scanner_contract_lower_token",
    "scanner_contract_nonnegative_int",
    "scanner_contract_text",
    "scanner_failure_evidence_record",
    "scanner_failure_evidence_tags",
)
