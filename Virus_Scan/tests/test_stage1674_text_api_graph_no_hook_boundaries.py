from __future__ import annotations

from Virus_Scan.scanners import text_api_sequence, text_graph_enrichment


class HostileApiIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileApiName:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify api")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr api")


class HostileTextBlob:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test blob")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify blob")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr blob")


def _lower(values):
    return {value.lower() for value in values if type(value) is str}


def test_stage1674_text_api_extraction_rejects_hostile_blob_without_hooks():
    HostileTextBlob.touched = 0

    calls = text_api_sequence.extract_api_calls(HostileTextBlob())
    sequence = text_api_sequence.extract_api_sequence_from_blob(HostileTextBlob())

    assert HostileTextBlob.touched == 0
    assert "unsafe_api_extract_text_rejected" in calls
    assert "scanner_failure_evidence:text:api_extract" in calls
    assert "unsafe_api_sequence_extract_text_rejected" in sequence
    assert "scanner_failure_evidence:text:api_sequence_extract" in sequence


def test_stage1674_text_api_sequence_rejects_hostile_log_line_without_hooks():
    HostileTextBlob.touched = 0

    sequence = text_api_sequence.build_api_sequence([HostileTextBlob()], strings_blob="")

    assert HostileTextBlob.touched == 0
    assert "unsafe_api_log_sequence_extract_text_rejected" in sequence
    assert "scanner_failure_evidence:text:api_log_sequence_extract" in sequence


def test_stage1674_text_graph_rejects_hostile_api_iterable_without_hooks():
    HostileApiIterable.touched = 0

    result = text_graph_enrichment.enrich_with_api_and_graph(text_graph_enrichment.TextGraphEnrichmentRequest(
        "node",
        strings_blob="",
        api_extractor=lambda _blob: HostileApiIterable(),
        sequence_builder=lambda _lines, strings_blob="": [],
        string_scanner=lambda *_args, **_kwargs: [],
    ))

    assert HostileApiIterable.touched == 0
    assert result["api_calls"].__class__ is HostileApiIterable
    tags = _lower(result["api_tags"])
    assert "text_api_calls_iterable_unavailable_scan_error" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "scanner_failure_evidence:text:api_graph" in tags


def test_stage1674_text_graph_rejects_hostile_api_name_without_hooks():
    HostileApiName.touched = 0

    result = text_graph_enrichment.enrich_with_api_and_graph(text_graph_enrichment.TextGraphEnrichmentRequest(
        "node",
        strings_blob="",
        api_extractor=lambda _blob: [HostileApiName()],
        sequence_builder=lambda _lines, strings_blob="": [HostileApiName()],
        string_scanner=lambda *_args, **_kwargs: [],
    ))

    assert HostileApiName.touched == 0
    tags = _lower(result["api_tags"])
    assert "unsafe_api_failure_tag_text_rejected" in tags
    assert "tag_normalization_failure_evidence" in tags
    assert "detection_stage_degraded" in tags
    assert result["graph_features"]["nodes"] == 0
