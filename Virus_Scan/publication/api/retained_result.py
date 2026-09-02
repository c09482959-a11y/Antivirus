"""Canonical public publication projection for bounded retained scheduler results."""
from __future__ import annotations

from Virus_Scan.publication.json_finalization.compact_record import compact_result_record
from Virus_Scan.publication.json_finalization.stream_identity import record_with_stream_identity
from Virus_Scan.publication.json_finalization.stream_record import drop_volatile_result_fields
from Virus_Scan.runtime.api import deterministic_mode_enabled


def build_retained_publication_record(record: object, output_path: str) -> dict[str, object]:
    """Build the one compact publication record retained before final JSON."""
    identified = record_with_stream_identity(record, output_path)
    final_input = drop_volatile_result_fields(identified) if deterministic_mode_enabled() else identified
    compact = compact_result_record(final_input)
    if type(compact) is not dict:
        raise TypeError("retained_result_compact_exact_dict_required")
    return compact


__all__ = ("build_retained_publication_record",)
