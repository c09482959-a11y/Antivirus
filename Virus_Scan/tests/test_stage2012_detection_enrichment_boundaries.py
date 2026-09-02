from __future__ import annotations

from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
import ast
from pathlib import Path

from Virus_Scan.detection.enrichment.full_analysis.api_context import build_detection_api_context
from Virus_Scan.detection.enrichment.full_analysis.boundaries import fa_mapping
from Virus_Scan.detection.enrichment.strings.contextual.decoded_payloads import decoded_payload_tags
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence


class HostileRecord:
    touched = 0

    def __getattr__(self, name):  # pragma: no cover - failure proves caller-owned lookup executed
        type(self).touched += 1
        raise AssertionError("decoded-payload record getattr must not execute")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("decoded-payload record str must not execute")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("decoded-payload record bool must not execute")


class HostileMapping(dict):
    touched = 0

    def keys(self):  # pragma: no cover - failure proves caller-owned mapping method executed
        type(self).touched += 1
        raise AssertionError("mapping keys hook must not execute")

    def items(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("mapping items hook must not execute")


class PlainDecodedRecord:
    touched = 0

    def __init__(self) -> None:
        self.text = "powershell http://example.test"
        self.encoding = "base64"
        self.decode_chain = ("base64",)

    def __getattr__(self, name):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("plain record unknown getattr must not execute")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("plain record str must not execute")


def test_stage2012_api_graph_failure_is_degraded_not_clean_fallback() -> None:
    def failing_api_graph(path, strings_blob, tags, *, strings_already_enriched, precomputed_tags):
        raise RuntimeError("stage2012 injected graph failure")

    facts = build_detection_api_context(
        path="game/script.rpy", tags=("renpy_script",), strings_blob="ShellExecuteW",
        strings_already_enriched=False, api_graph_enricher=failing_api_graph,
    )

    assert facts.api_result["degraded"] is True
    assert facts.api_result["degraded_stage"] == "api_graph_enrichment"
    assert facts.api_result["final_json_must_record"] is True
    assert facts.api_result["replay_record_required"] is True
    assert facts.api_result["failure_evidence"][0]["stage_name"] == "api_graph_enrichment"
    assert any(record["stage_name"] == "api_graph_enrichment" for record in facts.failure_evidence)


def test_stage2012_full_analysis_mapping_uses_exact_dict_boundary_without_keys_hook() -> None:
    HostileMapping.touched = 0
    mapped = HostileMapping({"safe": "value"})

    assert fa_mapping(mapped) == {"safe": "value"}
    assert HostileMapping.touched == 0


def test_stage2012_decoded_payload_records_do_not_use_getattr_or_str_hooks() -> None:
    HostileRecord.touched = 0
    PlainDecodedRecord.touched = 0

    assert decoded_payload_tags("", finalize=False, decoded_payloads=(HostileRecord(),)) == []
    tags = set(decoded_payload_tags("", path="payload.txt", finalize=False, decoded_payloads=(PlainDecodedRecord(),)))

    assert "decoded_base64_payload" in tags
    assert "decoded_payload_rescanned" in tags
    assert {"payload_decode_confirmed", "network_download", "script_execution"} <= tags
    assert "decoded_base64_download_execute_chain" not in tags
    chain_evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(sorted(tags))))
    assert any(
        decision.candidate.chain_id == "anchor:decoded_network_execution"
        and decision.status == "candidate"
        for decision in chain_evidence.decisions
    )
    assert HostileRecord.touched == 0
    assert PlainDecodedRecord.touched == 0


def test_stage2012_detection_enrichment_source_boundaries_do_not_regress() -> None:
    forbidden_snippets = {
        Path("Virus_Scan/detection/enrichment/full_analysis/api_context.py"): (
            "_fallback_api_enrichment",
            "return _fallback_api_enrichment",
        ),
        Path("Virus_Scan/detection/enrichment/full_analysis/boundaries.py"): (
            "value.keys()",
            "default=f\"<unavailable_key_",
        ),
        Path("Virus_Scan/detection/enrichment/strings/contextual/decoded_payloads.py"): (
            "getattr(record, name",
            "str(strings_blob or",
            "f\"decoded_{",
        ),
        Path("Virus_Scan/detection/enrichment/strings/raw_stage_strings.py"): (
            "str(\"\" if data is None else data)",
            "lowered = f\" ",
        ),
        Path("Virus_Scan/detection/enrichment/strings/contextual/js_execution_model.py"): (
            "script_to_process_chain",
        ),
        Path("Virus_Scan/detection/enrichment/strings/contextual/rpgm_js_ast.py"): (
            "script_to_process_chain",
        ),
    }
    for path, snippets in forbidden_snippets.items():
        source = path.read_text(encoding="utf-8")
        for snippet in snippets:
            assert snippet not in source

    for path in forbidden_snippets:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assert [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
