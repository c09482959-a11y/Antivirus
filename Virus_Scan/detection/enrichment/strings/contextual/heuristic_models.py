"""Canonical contextual heuristic-model enrichment ownership."""

from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.heuristics.downloader import evaluate_downloader_behavior
from Virus_Scan.detection.heuristics.game_engine_threats import evaluate_game_engine_threats
from Virus_Scan.heuristics.script_exec import evaluate_script_execution
from Virus_Scan.detection.enrichment.text_boundary import detection_enrichment_text_or_empty


def collect_central_heuristic_tags(text: object, *, path: object=None, source: object='strings') -> object:
    """Return tags from central heuristic evaluators without mutating detection state."""
    tags = []
    try:
        source_text = detection_enrichment_text_or_empty(path)
        if not source_text:
            source_text = detection_enrichment_text_or_empty(source)
        hres = evaluate_script_execution(text, source=source_text)
        tags.extend(hres.get('tags') or [])
        dres = evaluate_downloader_behavior(text, source=source_text)
        tags.extend(dres.get('tags') or [])
        gres = evaluate_game_engine_threats(text, path=source_text)
        tags.extend(gres.get('tags') or [])
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        tags.extend(['heuristic_model_failure_evidence', 'detection_stage_degraded'])
    return tags
