"""Canonical scanner-owned pickle public pipeline.

This module is the bounded public API for the pickle scanner subdomain. It
assembles opcode analysis, embedded-payload inspection, Ren'Py pickle handling,
fast escalation, and evidence-tag publication without owning their internals.
"""
from __future__ import annotations

from Virus_Scan.scanners.pickle.literals import pickle_fragment_decode_records_from_analysis
from Virus_Scan.scanners.pickle.opcode_analysis import analyze_pickle_opcode_graph
from Virus_Scan.scanners.pickle.embedded_payloads import pickle_embedded_payload_tags
from Virus_Scan.scanners.pickle.graph_tags import (
    detect_python_pickle_opcode_exec,
    pickle_opcode_graph_tags,
    unify_pickle_detection_tags,
)
from Virus_Scan.scanners.pickle.escalation import pickle_fast_escalation_prefilter
from Virus_Scan.scanners.pickle.source_detection import renpy_source_pickle_injection_tags

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
