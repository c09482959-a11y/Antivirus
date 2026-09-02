"""Public detection execution entrypoints for production callers."""
from __future__ import annotations

from Virus_Scan.detection.enrichment.prefilter.scan import strict_fast_prefilter
from Virus_Scan.detection.orchestration.full_analysis.pipeline import analyze_file_full_observe_only

__all__ = (
    "analyze_file_full_observe_only",
    "strict_fast_prefilter",
)
