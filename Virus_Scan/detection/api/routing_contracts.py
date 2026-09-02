"""Public detection contracts consumed by routing code.

Routing chooses file-processing paths and may request detection-owned enrichment,
stage, and profile signals only through this bounded public API.
"""
from __future__ import annotations

from Virus_Scan.detection.correlation.temporal.timeline import extension_timeline_anomaly
from Virus_Scan.detection.enrichment.pe_analysis.binary_static import scan_binary
from Virus_Scan.detection.enrichment.strings.micro_stage import micro_stage_collect
from Virus_Scan.detection.evidence.artifacts.scan_cache import remember_scan_evidence
from Virus_Scan.detection.evidence.relationships.stage_collector_merge import merge_stage_collector_results
from Virus_Scan.detection.evidence.timelines.stage_event import emit_stage_event
from Virus_Scan.detection.scoring.weighting.stage_enrichment import staged_enrichment_score
from Virus_Scan.detection.tags.evidence_generation import (
    TagEvidenceGeneration,
    finalize_tag_evidence_generation,
    merge_tag_evidence_inputs,
)
from Virus_Scan.detection.tags.heuristics.finalization import validate_tag_evidence_input_for_path
from Virus_Scan.detection.tags.heuristics.vocabulary import sanitize_tag_part

__all__ = (
    "emit_stage_event",
    "extension_timeline_anomaly",
    "TagEvidenceGeneration",
    "finalize_tag_evidence_generation",
    "merge_tag_evidence_inputs",
    "merge_stage_collector_results",
    "micro_stage_collect",
    "remember_scan_evidence",
    "sanitize_tag_part",
    "scan_binary",
    "staged_enrichment_score",
    "validate_tag_evidence_input_for_path",
)
