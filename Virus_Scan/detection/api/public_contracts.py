"""Public detection contracts for cross-domain production callers.

The functions exported here remain owned by detection; scheduler/reporting code
imports this module instead of reaching into detection implementation packages.
"""
from __future__ import annotations

from Virus_Scan.detection.enrichment.pe_analysis.dotnet_static import scan_dotnet_file
from Virus_Scan.detection.enrichment.strings.contextual.decoded_payloads import decoded_payload_tags
from Virus_Scan.detection.enrichment.strings.contextual.js_execution_model import umige_js_execution_model_tags
from Virus_Scan.detection.enrichment.strings.contextual.scan import ContextualTagScanRequest, contextual_tag_scan
from Virus_Scan.detection.enrichment.strings.micro_stage import micro_stage_collect
from Virus_Scan.detection.evidence.artifacts.scan_cache import remember_scan_evidence
from Virus_Scan.contracts.probabilistic_evidence import probabilistic_evidence_summary
from Virus_Scan.detection.profiles.family_scan import explicit_missed_family_tag_scan
from Virus_Scan.detection.scoring.weighting.stage_enrichment import staged_enrichment_score
from Virus_Scan.contracts.tag_evidence import contextual_dangerous_anchor_hits
from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation
from Virus_Scan.detection.tags.heuristics.strict_prefilter_policy import STRICT_FAST_PREFILTER_TAG_MAP

__all__ = (
    "ContextualTagScanRequest",
    "STRICT_FAST_PREFILTER_TAG_MAP",
    "contextual_dangerous_anchor_hits",
    "contextual_tag_scan",
    "decoded_payload_tags",
    "explicit_missed_family_tag_scan",
    "finalize_tag_evidence_generation",
    "micro_stage_collect",
    "probabilistic_evidence_summary",
    "remember_scan_evidence",
    "scan_dotnet_file",
    "staged_enrichment_score",
    "umige_js_execution_model_tags",
)
