from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
# Stage 4 real split module for reporting/summary.py.
# Exact v27c function bodies are copied here; no exec-string module body is used.
from Virus_Scan.utils.probability import score_to_probability as _score_to_probability
from Virus_Scan.runtime.api import log_error, record_suppressed_failure
from Virus_Scan.contracts.probabilistic_evidence import correlation_group_summary, probabilistic_evidence_summary
from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_mapping_items


def _summary_mapping_get(mapping: object, key: object, default: object=None) -> object:
    if type(key) is not str:
        return default
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for candidate_key, value in items:
        if type(candidate_key) is str and str.__eq__(candidate_key, key):
            return value
    return default


def _summary_count(mapping: object, key: object) -> object:
    value = _summary_mapping_get(mapping, key, 0)
    count, _reason = no_hook_exact_nonnegative_int(value, default=0, allow_exact_text=True)
    return count

def layer_probability_summary(layers: object) -> object:
    """Normalize the four named layers into probability-like signals."""
    if type(layers) is not dict:
        layers = {}
    quick = _summary_mapping_get(layers, "quick", {})
    stage = _summary_mapping_get(layers, "stage", {})
    graph = _summary_mapping_get(layers, "graph", {})
    intel = _summary_mapping_get(layers, "intel", {})
    return {
        "quick_static_probability": _score_to_probability(_summary_mapping_get(quick, "score", 0.0), midpoint=35.0, scale=18.0),
        "stage_probability": _score_to_probability(_summary_mapping_get(stage, "score", 0.0), midpoint=40.0, scale=18.0),
        "graph_probability": _score_to_probability(_summary_mapping_get(graph, "score", 0.0), midpoint=42.0, scale=18.0),
        "threat_intel_probability": _score_to_probability(_summary_mapping_get(intel, "score", 0.0), midpoint=38.0, scale=16.0),
    }

__all__ = ('correlation_group_summary', 'layer_probability_summary', 'probabilistic_evidence_summary')
