"""Publication-owned fast, recoverable final JSON result finalization.

This module is the stable publication API entrypoint. Implementation is
decomposed under :mod:`Virus_Scan.publication.json_finalization` so final JSON
streaming, compact-record projection, scheduler evidence projection, and model
evidence projection remain bounded publication-owned responsibilities.
"""
from __future__ import annotations

from Virus_Scan.publication.json_finalization.compact_record import compact_result_record
from Virus_Scan.publication.json_finalization.error_fields import build_compact_error_record
from Virus_Scan.publication.json_finalization.normalization import normalize_compact_result_record
from Virus_Scan.publication.json_finalization.scheduler_projection import existing_scheduler_final_json_fields
from Virus_Scan.publication.json_finalization.partial_results import (
    load_partial_results,
    recover_results_from_partial,
)
from Virus_Scan.publication.json_finalization.streaming import (
    finalize_scan_results,
    write_partial_scan_results,
)
from Virus_Scan.publication.json_finalization.success_context import compact_success_context

__all__ = (
    "build_compact_error_record",
    "compact_result_record",
    "compact_success_context",
    "existing_scheduler_final_json_fields",
    "finalize_scan_results",
    "load_partial_results",
    "normalize_compact_result_record",
    "recover_results_from_partial",
    "write_partial_scan_results",
)
