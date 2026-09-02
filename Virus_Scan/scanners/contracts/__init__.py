"""Scanner-owned immutable result/evidence contracts."""

from Virus_Scan.scanners.contracts.payload_result import PayloadDecodeResult
from Virus_Scan.scanners.contracts.binary_result import BinaryAnalysisResult
from Virus_Scan.scanners.contracts.scanner_evidence import (
    ScannerFailureEvidence,
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

__all__ = (
    "BinaryAnalysisResult",
    "PayloadDecodeResult",
    "ScannerFailureEvidence",
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
