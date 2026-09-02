"""Opcode-graph to scanner tag projection for pickle scanning."""
from __future__ import annotations

from Virus_Scan.runtime.api import is_programmer_error, scanner_failure_tags
from Virus_Scan.scanners.contracts import scanner_contract_error_message, scanner_contract_join
from Virus_Scan.scanners.contracts.scanner_evidence import scanner_failure_evidence_tags
from Virus_Scan.runtime.api import log_error
from Virus_Scan.scanners.pickle.fragment_tags import pickle_fragment_tags
from Virus_Scan.scanners.pickle.graph_base import base_opcode_graph_tags, unify_pickle_detection_tags
from Virus_Scan.scanners.pickle.literals import _iter_pickle_fragment_decode_records_from_analysis
from Virus_Scan.scanners.pickle.opcode_analysis import analyze_pickle_opcode_graph
from Virus_Scan.scanners.pickle.source_opcode_exec import detect_python_pickle_opcode_exec
from Virus_Scan.scanners.pickle.trigger_evidence import pickle_trigger_summaries

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError
)


def pickle_opcode_graph_tags(data: object = None, path: object = None) -> object:
    """Return tags from opcode-level pickle graph reconstruction."""
    tags = []
    try:
        try:
            analysis = analyze_pickle_opcode_graph(b'' if data is None else data)
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
            if is_programmer_error(exc):
                raise
            return scanner_failure_evidence_tags(
                'pickle',
                'pickle_opcode_graph',
                exc,
                ['pickle_opcode_graph_scan_error'],
                input_path=path,
                state='degraded',
                error_category='pickle_opcode_analyzer_failure',
                error_source='pickle.graph_tags.analyze',
                file_type='pickle',
            )
        if not analysis.get('valid_pickle'):
            if int(analysis.get('errors') or 0) > 0:
                return scanner_failure_evidence_tags(
                    'pickle',
                    'pickle_opcode_graph',
                    ValueError('pickle opcode parse failure'),
                    ['pickle_opcode_graph_scan_error'],
                    input_path=path,
                    state='degraded',
                    error_category='pickle_opcode_parse_failure',
                    error_source='pickle.graph_tags.pickle_opcode_graph_tags',
                    file_type='pickle',
                )
            return []
        tags.extend(base_opcode_graph_tags(analysis, path=path))
        if int(analysis.get('errors') or 0) > 0:
            tags.extend(scanner_failure_evidence_tags(
                'pickle',
                'pickle_opcode_graph',
                ValueError('pickle opcode parse failure'),
                ['pickle_opcode_graph_scan_error'],
                input_path=path,
                state='degraded',
                error_category='pickle_opcode_parse_failure',
                error_source='pickle.graph_tags.pickle_opcode_graph_tags',
                file_type='pickle',
            ))
        if analysis.get('has_exec_chain'):
            pickle_trigger_summaries(analysis)
        for rec in _iter_pickle_fragment_decode_records_from_analysis(analysis):
            tags.extend(pickle_fragment_tags(rec, path=path))
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        if is_programmer_error(exc):
            raise
        log_error(scanner_contract_join('pickle_opcode_graph_tags failed: ', scanner_contract_error_message(exc)))
        tags.extend(scanner_failure_tags('pickle_opcode_graph_tags', exc, [*tags, 'pickle_opcode_graph_scan_error']))
    return unify_pickle_detection_tags(tags, path=path)


__all__ = ('detect_python_pickle_opcode_exec', 'pickle_opcode_graph_tags', 'unify_pickle_detection_tags')
