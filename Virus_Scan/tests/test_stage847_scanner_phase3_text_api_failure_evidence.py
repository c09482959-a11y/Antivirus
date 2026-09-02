from Virus_Scan.scanners import text_validation_gates
from Virus_Scan.scanners import text_api_sequence, text_graph_enrichment


class _BrokenApiRegex:
    def finditer(self, _value):
        raise ValueError("synthetic API regex failure")


def _lower(values):
    return {str(v).lower() for v in values or []}


def test_extract_api_calls_failure_returns_scanner_evidence():
    calls = text_api_sequence.extract_api_calls("CreateProcessW powershell", api_regex=_BrokenApiRegex())
    low = _lower(calls)

    assert "text_api_extract_failed" in low
    assert "api_extract_scan_error" in low
    assert "scanner_failure_evidence_recorded" in low
    assert "scanner_failure_evidence:text:api_extract" in low


def test_enrich_raw_context_preserves_api_failure_evidence():
    broken_regex = _BrokenApiRegex()
    result = text_graph_enrichment.enrich_with_api_and_graph(text_graph_enrichment.TextGraphEnrichmentRequest(
        "node",
        strings_blob="CreateProcessW powershell",
        api_extractor=lambda blob: text_api_sequence.extract_api_calls(blob, api_regex=broken_regex),
        sequence_builder=lambda lines, strings_blob='': text_api_sequence.build_api_sequence(lines, strings_blob=strings_blob, api_regex=broken_regex),
        string_scanner=lambda *_args, **_kwargs: [],
    ))
    low_api_calls = _lower(result.get("api_calls"))
    low_api_tags = _lower(result.get("api_tags"))
    low_sequence = _lower(result.get("sequence"))

    assert "text_api_extract_failed" in low_api_calls
    assert "api_extract_scan_error" in low_api_tags
    assert "scanner_failure_evidence:text:api_extract" in low_api_tags
    assert "api_sequence_extract_scan_error" in low_sequence


def test_library_baseline_hard_proof_fails_closed_on_context_parser_error():
    def boom(_text):
        raise ValueError("synthetic context parser failure")

    assert text_validation_gates.library_baseline_has_hard_proof(
        [],
        "powershell -enc",
        validation_text=boom,
        logger=lambda *_args, **_kwargs: None,
    ) is True
