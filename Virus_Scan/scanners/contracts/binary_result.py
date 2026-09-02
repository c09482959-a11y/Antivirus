"""Immutable binary scanner result contracts owned by scanners."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scanners.contracts.scanner_evidence import (
    freeze_scanner_evidence_records,
    materialize_scanner_evidence_records,
    scanner_contract_bool,
    scanner_contract_error_message,
    scanner_contract_join,
    scanner_contract_lower_token,
    scanner_contract_text,
    scanner_failure_evidence_record,
    scanner_failure_evidence_tags,
)


@dataclass(frozen=True, slots=True)
class BinaryMalformedRequest:
    """Immutable input contract for malformed binary result publication."""

    scanner_name: str
    stage: str
    error: BaseException | str
    input_path: object = ""
    file_type: str = "binary"
    error_category: str = "malformed_binary_input"


@dataclass(frozen=True, slots=True)
class BinaryAnalysisResult:
    scanner_name: str
    stage: str
    detected: bool
    ok: bool
    failure_tags: tuple[str, ...] = ()
    failure_evidence: tuple[Mapping[str, object], ...] = ()
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "scanner_name", scanner_contract_text(self.scanner_name, replacement="binary"))
        object.__setattr__(self, "stage", scanner_contract_text(self.stage, replacement="binary"))
        object.__setattr__(self, "detected", scanner_contract_bool(self.detected, replacement=False))
        object.__setattr__(self, "ok", scanner_contract_bool(self.ok, replacement=False))
        object.__setattr__(self, "failure_tags", tuple(
            scanner_contract_text(tag, replacement="scanner_failure_tag_rejected")
            for tag in (self.failure_tags if self.failure_tags is not None else ())
        ))
        object.__setattr__(self, "failure_evidence", freeze_scanner_evidence_records(self.failure_evidence))
        object.__setattr__(self, "reason", scanner_contract_text(self.reason, replacement=""))

    @classmethod
    def detected_result(cls, scanner_name: str, stage: str) -> "BinaryAnalysisResult":
        return cls(scanner_contract_text(scanner_name, replacement="binary"), scanner_contract_text(stage, replacement="binary"), detected=True, ok=True)

    @classmethod
    def unsupported_result(cls, scanner_name: str, stage: str) -> "BinaryAnalysisResult":
        return cls(scanner_contract_text(scanner_name, replacement="binary"), scanner_contract_text(stage, replacement="binary"), detected=False, ok=True)

    @classmethod
    def malformed(
        cls, request: BinaryMalformedRequest
    ) -> "BinaryAnalysisResult":
        """Build a malformed result from the canonical immutable request."""
        tags = scanner_failure_evidence_tags(
            request.scanner_name,
            request.stage,
            request.error,
            [
                "binary_parse_failed",
                scanner_contract_join(
                    scanner_contract_lower_token(request.stage, replacement="binary"),
                    "_parse_failed",
                ),
            ],
            input_path=request.input_path,
            state="malformed",
            error_category=request.error_category,
            error_source=scanner_contract_join(
                "binary.", scanner_contract_text(request.stage, replacement="binary")
            ),
            file_type=request.file_type,
        )
        evidence = scanner_failure_evidence_record(
            request.scanner_name,
            request.stage,
            request.error,
            input_path=request.input_path,
            state="malformed",
            error_category=request.error_category,
            error_source=scanner_contract_join(
                "binary.", scanner_contract_text(request.stage, replacement="binary")
            ),
            file_type=request.file_type,
        )
        return cls(
            scanner_contract_text(request.scanner_name, replacement="binary"),
            scanner_contract_text(request.stage, replacement="binary"),
            detected=False,
            ok=False,
            failure_tags=tuple(tags),
            failure_evidence=(evidence,),
            reason=scanner_contract_error_message(request.error),
        )

    def to_metadata(self) -> dict[str, object]:
        if self.ok:
            return {"is_dotnet": bool(self.detected)}
        return {
            "is_dotnet": False,
            "error": True,
            "scanner_degraded": True,
            "tags": list(self.failure_tags),
            "scanner_failure_evidence": materialize_scanner_evidence_records(self.failure_evidence),
            "scan_integrity": {
                "file_failed": True,
                "had_degraded_stage": True,
                "allow_learning": False,
                "error": self.reason,
                "scanner_failure_evidence": materialize_scanner_evidence_records(self.failure_evidence),
                "final_json_must_record": True,
            },
        }


__all__ = (
    'BinaryAnalysisResult',
    'BinaryMalformedRequest',
)
