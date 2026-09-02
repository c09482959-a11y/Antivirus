"""Detection-owned API graph enrichment for full analysis.

This module builds immutable API sequence/graph evidence. It does not mutate the
runtime/model graph directly; downstream publication owners may consume the
returned graph_publication_edges if graph persistence is required.
"""
from __future__ import annotations
from typing import TYPE_CHECKING


from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.enrichment.text_boundary import detection_enrichment_text_or_empty
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.contracts.api_behavior import build_api_regex
from Virus_Scan.detection.correlation.temporal.behavior_timeline import build_behavior_timeline
from Virus_Scan.detection.registries.immutability import freeze_registry_value
from Virus_Scan.detection.tags.process.api_tags import infer_tags_from_api
from Virus_Scan.contracts.graph_publication import api_graph_publication_edges
from Virus_Scan.contracts.call_graph_projection import immutable_api_call_graph, api_call_graph_features

if TYPE_CHECKING:
    from collections.abc import Iterator

API_REGEX = build_api_regex()


def _safe_api_text(value: object) -> str:
    return detection_enrichment_text_or_empty(value)


def _api_sequence_values(sequence: object) -> list[str]:
    values: list[str] = []
    iterator: Iterator[object] = iter(())
    if sequence is not None:
        try:
            iterator = iter(sequence)
        except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
            iterator = iter(())
    while True:
        try:
            item = next(iterator)
        except StopIteration:
            break
        except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
            break
        text = _safe_api_text(item)
        if text:
            values.append(text)
    return values


def api_ngrams(sequence: object, n: object=3) -> object:
    values = _api_sequence_values(sequence)
    if len(values) < n:
        return []
    return [tuple(values[i:i + n]) for i in range(len(values) - n + 1)]


def extract_api_calls(strings_blob: object) -> object:
    """Extract deduplicated API calls in first-seen order."""
    text = _safe_api_text(strings_blob)
    if not text:
        return []
    matches = [match.group(0) for match in API_REGEX.finditer(text)]
    return list(dict.fromkeys(matches))


def extract_api_sequence_from_blob(strings_blob: object) -> object:
    """Return every API occurrence in first-seen order, including repeats."""
    text = _safe_api_text(strings_blob)
    if not text:
        return []
    return [match.group(0) for match in API_REGEX.finditer(text)]


def build_api_sequence(log_lines: object=None, strings_blob: object='') -> object:
    """Build an ordered API sequence from logs, falling back to the static blob."""
    sequence = []
    for line in _api_sequence_values(log_lines):
        sequence.extend(match.group(0) for match in API_REGEX.finditer(line))
    if sequence:
        return sequence
    return extract_api_sequence_from_blob(strings_blob)



def enrich_with_api_and_graph(node: object, strings_blob: object='', log_lines: object=None, *, strings_already_enriched: object=False, precomputed_tags: object=None) -> object:
    """Build API/call-graph enrichment without scanner/model graph mutation."""
    del strings_already_enriched
    source_text = _safe_api_text(strings_blob)
    api_calls = extract_api_calls(source_text)
    sequence = build_api_sequence(log_lines, strings_blob=source_text)
    ngrams = api_ngrams(sequence)
    call_graph = immutable_api_call_graph(sequence)
    graph_features = api_call_graph_features(call_graph)
    string_tags = ordered_unique_tags(precomputed_tags)
    api_tags = infer_tags_from_api(api_calls, string_tags)
    behavior_timeline, ordered_events = build_behavior_timeline(
        strings_blob=source_text,
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
        'ngrams': ngrams,
        'call_graph': dict(call_graph),
        'graph_features': graph_features,
        'graph_publication_edges': freeze_registry_value(api_graph_publication_edges(node, api_calls, api_tags, call_graph)),
    }


__all__ = ('build_api_sequence', 'build_behavior_timeline', 'enrich_with_api_and_graph', 'extract_api_calls')
