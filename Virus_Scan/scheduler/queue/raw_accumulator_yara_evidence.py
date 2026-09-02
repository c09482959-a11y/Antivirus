"""Canonical raw-queue YARA scan-result accumulation."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.yara_hits import (
    YaraScanResult,
    unavailable_yara_scan_result,
)


def _scan_result_record(value: object) -> dict[str, object] | None:
    if type(value) is not dict:
        return None
    try:
        return YaraScanResult.from_record(value).to_record()
    except (TypeError, ValueError):
        return None


def append_accumulator_yara_evidence(
    data: dict[str, object],
    result_data: Mapping[str, object],
) -> None:
    """Admit exactly one canonical YARA result for a raw file scan."""
    incoming = _scan_result_record(dict.get(result_data, "yara_evidence"))
    if incoming is None:
        return
    current = _scan_result_record(dict.get(data, "yara_evidence"))
    if current is None:
        data["yara_evidence"] = incoming
        return
    if current == incoming:
        return
    data["yara_evidence"] = unavailable_yara_scan_result(
        "duplicate_conflicting_yara_scan_results", status="failed"
    ).to_record()
    data["degraded"] = True
    errors = dict.get(data, "errors")
    bounded = list(errors) if type(errors) is list else []
    bounded.append("duplicate conflicting YARA scan results rejected")
    data["errors"] = bounded[-128:]


__all__ = ("append_accumulator_yara_evidence",)
