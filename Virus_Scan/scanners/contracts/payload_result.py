"""Immutable payload decoding result contracts owned by scanners."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scanners.contracts.scanner_evidence import (
    freeze_scanner_evidence_records,
    materialize_scanner_evidence_records,
    scanner_contract_bool,
    scanner_contract_bytes,
    scanner_contract_error_message,
    scanner_contract_join,
    scanner_contract_lower_token,
    scanner_contract_nonnegative_int,
    scanner_contract_text,
    scanner_failure_evidence_record,
    scanner_failure_evidence_tags,
)


@dataclass(frozen=True, slots=True)
class PayloadFailureRequest:
    """Immutable input contract for failed payload decode publication."""

    encoding: str
    stage: str
    error: BaseException | str
    depth: int = 0
    state: str = "malformed"
    error_category: str = "payload_decode_failure"


@dataclass(frozen=True, slots=True)
class PayloadDecodeResult:
    encoding: str
    decoded: bytes
    ok: bool
    failure_tags: tuple[str, ...] = ()
    failure_evidence: tuple[Mapping[str, object], ...] = ()
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "encoding", scanner_contract_text(self.encoding, replacement="payload"))
        object.__setattr__(self, "decoded", scanner_contract_bytes(self.decoded))
        object.__setattr__(self, "ok", scanner_contract_bool(self.ok, replacement=False))
        object.__setattr__(self, "failure_tags", tuple(
            scanner_contract_text(tag, replacement="scanner_failure_tag_rejected")
            for tag in (self.failure_tags if self.failure_tags is not None else ())
        ))
        object.__setattr__(self, "failure_evidence", freeze_scanner_evidence_records(self.failure_evidence))
        object.__setattr__(self, "reason", scanner_contract_text(self.reason, replacement=""))

    @classmethod
    def success(cls, encoding: str, decoded: bytes) -> "PayloadDecodeResult":
        return cls(encoding=scanner_contract_text(encoding, replacement="payload"), decoded=scanner_contract_bytes(decoded), ok=True)

    @classmethod
    def failure(
        cls, request: PayloadFailureRequest
    ) -> "PayloadDecodeResult":
        """Build a failed decode result from the canonical immutable request."""
        tags = scanner_failure_evidence_tags(
            "payload_decode",
            request.stage,
            request.error,
            [
                "payload_decode_failed",
                scanner_contract_join(
                    scanner_contract_lower_token(request.encoding, replacement="payload"),
                    "_decode_failed",
                ),
            ],
            state=request.state,
            error_category=request.error_category,
        )
        evidence = scanner_failure_evidence_record(
            "payload_decode",
            request.stage,
            request.error,
            state=request.state,
            error_category=request.error_category,
            error_source=scanner_contract_join(
                "payload_decode.",
                scanner_contract_text(request.stage, replacement="unknown"),
            ),
            decode_depth=scanner_contract_nonnegative_int(request.depth, replacement=0),
        )
        return cls(
            encoding=scanner_contract_text(request.encoding, replacement="payload"),
            decoded=b"",
            ok=False,
            failure_tags=tuple(tags),
            failure_evidence=(evidence,),
            reason=scanner_contract_error_message(request.error),
        )

    def to_failure_record(self, *, depth: int = 0) -> dict[str, object]:
        return {
            "encoding": self.encoding,
            "depth": scanner_contract_nonnegative_int(depth, replacement=0),
            "parent": "",
            "raw_sample": "",
            "text": "",
            "byte_len": 0,
            "sha256": "",
            "evidence_id": scanner_contract_join("payload_decode_failure:", self.encoding),
            "decode_chain": [self.encoding],
            "binary_magic": "",
            "failure_tags": list(self.failure_tags),
            "failure_evidence": materialize_scanner_evidence_records(self.failure_evidence),
            "failure_reason": self.reason,
        }


__all__ = (
    'PayloadDecodeResult',
    'PayloadFailureRequest',
)
