"""Payload decode failure evidence construction."""
from __future__ import annotations


from Virus_Scan.scanners.contracts import scanner_contract_join, scanner_contract_nonnegative_int, scanner_contract_text, scanner_failure_evidence_record, scanner_failure_evidence_tags

def _payload_decode_failure_record(stage: str, error: BaseException | str, *, encoding: str = "", depth: int = 0) -> dict[str, object]:
    stage_text = scanner_contract_text(stage, replacement="payload_decode")
    encoding_text = scanner_contract_text(encoding, replacement=stage_text) or stage_text
    depth_value = scanner_contract_nonnegative_int(depth)
    tags = scanner_failure_evidence_tags(
        "payload_decode",
        stage_text,
        error,
        ["payload_decode_error"],
        state="degraded",
        error_category="payload_decode_failure",
    )
    return {
        "encoding": encoding_text,
        "depth": depth_value,
        "parent": "",
        "raw_sample": "",
        "text": "",
        "byte_len": 0,
        "sha256": "",
        "evidence_id": scanner_contract_join("payload_decode_failure:", stage_text),
        "decode_chain": [stage_text],
        "binary_magic": "",
        "failure_tags": tags,
        "failure_evidence": [
            scanner_failure_evidence_record(
                "payload_decode",
                stage_text,
                error,
                error_category="payload_decode_failure",
                error_source=scanner_contract_join("payload_decode.", stage_text),
                decode_depth=depth_value,
            )
        ],
    }

__all__ = ("_payload_decode_failure_record",)
