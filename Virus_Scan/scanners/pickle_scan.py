"""Public pickle scanner facade.

Canonical implementation lives in bounded scanner-owned pickle modules. This
module only preserves the historical public import surface while delegating each
behavior to one canonical implementation.
"""

from Virus_Scan.scanners.pickle.source_detection import (
    renpy_source_pickle_injection_tags,
)
from Virus_Scan.scanners.pickle.scanner import (
    analyze_pickle_opcode_graph,
    detect_python_pickle_opcode_exec,
    pickle_embedded_payload_tags,
    pickle_fast_escalation_prefilter,
    pickle_fragment_decode_records_from_analysis,
    pickle_opcode_graph_tags,
    unify_pickle_detection_tags,
)

__all__ = (
    'analyze_pickle_opcode_graph',
    'detect_python_pickle_opcode_exec',
    'pickle_embedded_payload_tags',
    'pickle_fast_escalation_prefilter',
    'pickle_fragment_decode_records_from_analysis',
    'pickle_opcode_graph_tags',
    'renpy_source_pickle_injection_tags',
    'unify_pickle_detection_tags',
)
