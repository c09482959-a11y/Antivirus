"""Canonical no-hook evidence identity scalar projection."""
from __future__ import annotations

import math

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_value


def evidence_identity_value(record: object, field_name: str) -> object:
    """Return a stable, hook-free scalar used in evidence dedupe identities."""

    value = scheduler_mapping_value(record, field_name)
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    return ("unsupported", field_name, no_hook_type_name(value))


__all__ = ("evidence_identity_value",)
