from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.tests.support.static_inventory import read_python_file

import json
import ast
from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.detection.scoring.weighting.stage_enrichment import staged_enrichment_score
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_evidence
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.yara.context_evidence import generic_yara_evidence_context



class HostileText:
    touched = 0

    def __str__(self):
        HostileText.touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        HostileText.touched += 1
        raise RuntimeError("do not call repr")


class HostileNumeric:
    touched = 0

    def __float__(self):
        HostileNumeric.touched += 1
        raise RuntimeError("do not call float")

    def __int__(self):
        HostileNumeric.touched += 1
        raise RuntimeError("do not call int")

    def __bool__(self):
        HostileNumeric.touched += 1
        raise RuntimeError("do not call bool")


class HostileIterable:
    touched = 0

    def __iter__(self):
        HostileIterable.touched += 1
        raise RuntimeError("do not iterate")


class HostileMapping(Mapping):
    touched = 0

    def __getitem__(self, key):
        HostileMapping.touched += 1
        raise RuntimeError("do not getitem")

    def __iter__(self):
        HostileMapping.touched += 1
        raise RuntimeError("do not iterate mapping")

    def __len__(self):
        HostileMapping.touched += 1
        raise RuntimeError("do not len")

    def get(self, key, default=None):
        HostileMapping.touched += 1
        raise RuntimeError("do not call get")

    def items(self):
        HostileMapping.touched += 1
        raise RuntimeError("do not call items")


def reset_hostiles():
    HostileText.touched = 0
    HostileNumeric.touched = 0
    HostileIterable.touched = 0
    HostileMapping.touched = 0


def test_stage_enrichment_rejects_hostile_stage_and_asset_score_without_hooks():
    reset_hostiles()

    evidence = scoreable_tag_evidence(
        physical_tag_evidence(("network_download", "process_exec")),
        allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )
    score, hits = staged_enrichment_score(
        evidence, evaluate_chain_evidence(tags=evidence), HostileText(),
        asset_score=HostileNumeric(),
    )

    assert HostileText.touched == 0
    assert HostileNumeric.touched == 0
    assert isinstance(score, float)
    assert hits == []


def test_yara_context_rejects_hostile_yara_input_without_text_hooks():
    reset_hostiles()
    context = generic_yara_evidence_context(HostileText())
    assert HostileText.touched == 0
    assert context.scan_status == "unavailable"
    assert context.probability_authority is False
    assert json.dumps(context.to_record(), sort_keys=True)



def test_yara_context_source_contains_no_name_keyword_probability_surface():
    source = read_python_file(Path("Virus_Scan/detection/scoring/yara/context_evidence.py"))
    tree = ast.parse(source)
    forbidden = (
        "YARA_RULE_CONFIDENCE_KEYWORDS",
        "CORRELATION_GROUP_KEYWORDS",
        "calibrated_score",
        "posterior",
        "yara_weight",
    )
    assert [snippet for snippet in forbidden if snippet in source] == []
    assert [node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
