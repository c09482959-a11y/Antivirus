"""Scanner-owned API graph observation for text scanner results.

The scanner extracts API calls, tags, sequence, and immutable graph publication
requests. It does not import model graph state or publish graph side effects;
publication/detection owners decide whether to persist returned edges.
"""

from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.runtime.api import scan_strings
from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_text
from Virus_Scan.scanners.text_api_sequence import api_ngrams, build_api_sequence, extract_api_calls
from Virus_Scan.scanners.text_api_mapping import infer_tags_from_api
from Virus_Scan.scanners.text_api_timeline import build_behavior_timeline
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.contracts.graph_publication import api_graph_publication_edges
from Virus_Scan.contracts.call_graph_projection import immutable_api_call_graph, api_call_graph_features


@dataclass(frozen=True, slots=True)
class TextGraphEnrichmentRequest:
    node: object
    strings_blob: object = ""
    log_lines: object = None
    strings_already_enriched: object = False
    precomputed_tags: object = None
    api_extractor: object = extract_api_calls
    sequence_builder: object = build_api_sequence
    string_scanner: object = scan_strings


def _api_failure_tags(api_calls: object) -> object:
    tags = []
    items = no_hook_sequence_items(api_calls)
    if api_calls is not None and not items and type(api_calls) not in (tuple, list, set, frozenset, str, bytes, bytearray):
        return [
            'text_api_calls_iterable_unavailable_scan_error',
            'scanner_failure_evidence_recorded',
            'scanner_failure_evidence:text:api_graph',
        ]
    for api in items:
        text, reason = no_hook_text(
            api,
            missing_reason='missing_api_failure_tag_text',
            unsupported_reason='unsafe_api_failure_tag_text_rejected',
        )
        if reason:
            tags.extend([
                'unsafe_api_failure_tag_text_rejected',
                'scanner_failure_evidence_recorded',
                'scanner_failure_evidence:text:api_graph',
            ])
            continue
        if (
            text.endswith('_scan_error')
            or text == 'scanner_failure_evidence_recorded'
            or text.startswith('scanner_failure_evidence:')
            or text == 'text_api_extract_failed'
        ):
            tags.append(text)
    return ordered_unique_tags(tags)


def _string_tags_for_node(node: object, strings_blob: object, strings_already_enriched: object, precomputed_tags: object, *, string_scanner: object = scan_strings) -> object:
    if strings_already_enriched:
        return list(precomputed_tags or [])
    return string_scanner(strings_blob, path=node)



def enrich_with_api_and_graph(request: TextGraphEnrichmentRequest) -> object:
    """Extract API evidence and return graph publication requests without side effects."""
    strings_blob_text, strings_blob_reason = no_hook_text(request.strings_blob, missing_reason='missing_graph_strings_blob', unsupported_reason='unsafe_graph_strings_blob_rejected')
    strings_blob = '' if strings_blob_reason else strings_blob_text
    log_lines = no_hook_sequence_items(request.log_lines)
    api_calls = request.api_extractor(strings_blob)
    sequence = request.sequence_builder(log_lines, strings_blob=strings_blob)
    call_graph = immutable_api_call_graph(sequence)
    graph_features = api_call_graph_features(call_graph)
    string_tags = _string_tags_for_node(request.node, strings_blob, request.strings_already_enriched, request.precomputed_tags, string_scanner=request.string_scanner)
    api_tags = ordered_unique_tags(_api_failure_tags(api_calls) + infer_tags_from_api(api_calls, string_tags))
    graph_publication_edges = api_graph_publication_edges(request.node, api_calls, api_tags, call_graph)
    behavior_timeline, ordered_events = build_behavior_timeline(
        strings_blob=strings_blob,
        api_calls=api_calls,
        api_sequence=sequence,
        tags=api_tags,
    )
    return {
        'api_calls': api_calls,
        'api_tags': api_tags,
        'string_tags': string_tags,
        'sequence': sequence,
        'behavior_timeline': behavior_timeline,
        'ordered_events': ordered_events,
        'ngrams': api_ngrams(sequence),
        'call_graph': call_graph,
        'graph_features': graph_features,
        'graph_publication_edges': graph_publication_edges,
    }




__all__ = (
    'TextGraphEnrichmentRequest',
    'enrich_with_api_and_graph',
)
