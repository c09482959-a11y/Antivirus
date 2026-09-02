"""Stage 1417: detection enrichment helpers bound hostile string/path inputs."""

from __future__ import annotations

from Virus_Scan.detection.enrichment.full_analysis.api_graph_context import (
    api_ngrams,
    build_api_sequence,
    enrich_with_api_and_graph,
    extract_api_calls,
)
from Virus_Scan.utils.fast_assets import (
    _hex_to_rpgm_key,
    png_decode_observation,
    sniff_recovered_rpgm_payload_type,
    validated_embedded_payload_hits,
)
from Virus_Scan.detection.enrichment.strings.raw_stage_strings import (
    iter_ordered_string_events,
    raw_stage_scan_strings,
    scan_hash_for_staging,
    stage_decode_latin1,
)


class HostileText:
    def __str__(self):  # pragma: no cover
        raise RuntimeError("hostile text")

    def __repr__(self):  # pragma: no cover
        raise RuntimeError("hostile repr")

    def __bool__(self):  # pragma: no cover
        raise RuntimeError("hostile bool")


class HostileIterable:
    def __iter__(self):  # pragma: no cover
        raise RuntimeError("hostile iterator")

    def __bool__(self):  # pragma: no cover
        raise RuntimeError("hostile bool")


class HostileBytes:
    def __bytes__(self):  # pragma: no cover
        raise RuntimeError("hostile bytes")

    def __bool__(self):  # pragma: no cover
        raise RuntimeError("hostile bool")


def test_stage1417_raw_stage_string_helpers_bound_hostile_text_and_paths() -> None:
    assert stage_decode_latin1(HostileText()) == "string_enrichment_input_unavailable"
    tags = raw_stage_scan_strings(HostileText())
    assert tags == []
    assert list(iter_ordered_string_events(HostileText())) == []
    assert len(scan_hash_for_staging(HostileText())) == 16

    normal = raw_stage_scan_strings("powershell -enc http://example")
    assert "powershell_exec" in normal
    assert "encoded_powershell" in normal
    assert "url_present" in normal


def test_stage1417_api_graph_enrichment_bounds_hostile_iterables_and_text() -> None:
    assert api_ngrams(HostileIterable()) == []
    assert extract_api_calls(HostileText()) == []
    assert build_api_sequence(HostileIterable(), strings_blob=HostileText()) == []

    enriched = enrich_with_api_and_graph(
        HostileText(),
        strings_blob=HostileText(),
        log_lines=HostileIterable(),
        precomputed_tags=HostileIterable(),
    )
    assert enriched["api_calls"] == []
    assert "tag_normalization_failure_evidence" in enriched["string_tags"]
    assert isinstance(enriched["graph_publication_edges"], tuple)


def test_stage1417_image_fast_triage_bounds_hostile_scalar_inputs() -> None:
    assert _hex_to_rpgm_key(HostileText()) is None
    assert sniff_recovered_rpgm_payload_type(HostileBytes(), ext=HostileText()) == ("encrypted_asset", [])
    assert validated_embedded_payload_hits(HostileBytes()) == []
    assert png_decode_observation(HostileBytes()) is None
