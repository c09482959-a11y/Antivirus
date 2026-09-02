from __future__ import annotations

from Virus_Scan.detection.enrichment.full_analysis.api_graph_context import (
    build_api_sequence,
    extract_api_calls,
)
from Virus_Scan.detection.enrichment.full_analysis.boundaries import fa_mapping, fa_text
from Virus_Scan.utils.fast_assets import _hex_to_rpgm_key
from Virus_Scan.detection.enrichment.strings.boundaries import enrichment_text_or_empty
from Virus_Scan.detection.enrichment.strings.contextual.scan import ContextualTagScanRequest, contextual_tag_scan


class HostileEnrichmentText:
    touched = 0

    def __str__(self):  # pragma: no cover - failure proves caller hook execution returned
        type(self).touched += 1
        raise AssertionError("detection enrichment __str__ must not execute")

    def __repr__(self):  # pragma: no cover - failure proves caller hook execution returned
        type(self).touched += 1
        raise AssertionError("detection enrichment __repr__ must not execute")

    def __bool__(self):  # pragma: no cover - failure proves caller hook execution returned
        type(self).touched += 1
        raise AssertionError("detection enrichment truthiness must not execute")


class PlainOwnedEnrichmentText:
    touched = 0

    def __init__(self, text: str) -> None:
        self._text = text

    def __str__(self):  # pragma: no cover - failure proves caller hook execution returned
        type(self).touched += 1
        raise AssertionError("plain enrichment __str__ must not execute")

    def __repr__(self):  # pragma: no cover - failure proves caller hook execution returned
        type(self).touched += 1
        raise AssertionError("plain enrichment __repr__ must not execute")

    def __bool__(self):  # pragma: no cover - failure proves caller hook execution returned
        type(self).touched += 1
        raise AssertionError("plain enrichment truthiness must not execute")


class HostileKey:
    touched = 0

    def __str__(self):  # pragma: no cover - failure proves caller hook execution returned
        type(self).touched += 1
        raise AssertionError("mapping key __str__ must not execute")

    def __repr__(self):  # pragma: no cover - failure proves caller hook execution returned
        type(self).touched += 1
        raise AssertionError("mapping key __repr__ must not execute")


class HostileMappingKeyText:
    def __init__(self) -> None:
        self.text = "owned_key"


def _reset() -> None:
    HostileEnrichmentText.touched = 0
    PlainOwnedEnrichmentText.touched = 0
    HostileKey.touched = 0


def test_detection_enrichment_text_boundaries_reject_unknown_text_without_str_hooks() -> None:
    _reset()
    hostile = HostileEnrichmentText()

    assert enrichment_text_or_empty(hostile) == ""
    assert fa_text(hostile, default="fallback") == "fallback"
    assert extract_api_calls(hostile) == []
    assert build_api_sequence(strings_blob=hostile) == []
    assert _hex_to_rpgm_key(hostile) is None

    assert HostileEnrichmentText.touched == 0


def test_detection_enrichment_text_boundaries_accept_plain_owned_text_without_str_hooks() -> None:
    _reset()
    owned = PlainOwnedEnrichmentText("os.system powershell -enc AAA http://example.test")

    assert enrichment_text_or_empty(owned).startswith("os.system powershell")
    tags = contextual_tag_scan(ContextualTagScanRequest(owned, path="game/script.rpy", source=PlainOwnedEnrichmentText("strings"), finalize=False))

    assert "process_exec" in tags
    assert "script_execution" in tags
    assert PlainOwnedEnrichmentText.touched == 0


def test_full_analysis_mapping_key_failure_evidence_does_not_stringify_unknown_keys() -> None:
    _reset()
    hostile_key = HostileKey()
    mapped = fa_mapping({hostile_key: "value", HostileMappingKeyText(): "owned"})

    assert "<unavailable_key_0>" in mapped
    assert mapped["owned_key"] == "owned"
    assert HostileKey.touched == 0
