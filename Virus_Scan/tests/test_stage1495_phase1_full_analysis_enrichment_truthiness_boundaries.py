from __future__ import annotations
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture

from collections.abc import Mapping

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.detection.enrichment.full_analysis.input_stage import prepare_analysis_inputs
from Virus_Scan.detection.enrichment.full_analysis.api_context import build_detection_api_context
from Virus_Scan.tests.support.canonical_yara_fixtures import (
    canonical_test_yara_no_match_result,
    canonical_test_yara_result,
)


class HostileSequence:
    def __init__(self, values):
        self._values = tuple(values)

    def __iter__(self):
        return iter(self._values)

    def __bool__(self):  # pragma: no cover - must never be reached
        raise AssertionError("caller-owned sequence truthiness was probed")


class HostileMapping(Mapping):
    def __init__(self, values):
        self._values = dict(values)

    def __getitem__(self, key):
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def get(self, key, default=None):
        return self._values.get(key, default)

    def __bool__(self):  # pragma: no cover - must never be reached
        raise AssertionError("caller-owned mapping truthiness was probed")



def test_stage1495_prepare_analysis_inputs_detaches_hostile_tags_and_preserves_canonical_yara_result(tmp_path):
    path = tmp_path / "game.rpy"
    path.write_text("label start:\n    pass\n", encoding="utf-8")

    facts = prepare_analysis_inputs(
        str(path),
        tags=HostileSequence(("renpy_script",)),
        yara_hits=canonical_test_yara_result(rule_name="hit_a"),
        strings_blob="renpy execution text",
        strings_already_enriched=True,
        artifact_read_snapshot=artifact_read_snapshot_fixture(path),
        attack_repository_digest=scan_session_snapshot_fixture().cache_execution_identity.attack_repository_digest,
    )

    assert "renpy_script" in facts.tags
    assert "hit_a" in facts.yara_hits
    assert facts.strings_blob == "renpy execution text"


def test_stage1495_prepare_analysis_inputs_detaches_hostile_string_scanner_output(tmp_path):
    path = tmp_path / "game.rpy"
    path.write_text("label start:\n    pass\n", encoding="utf-8")

    facts = prepare_analysis_inputs(
        str(path),
        tags=HostileSequence(("renpy_script",)),
        yara_hits=canonical_test_yara_no_match_result(),
        strings_blob="renpy execution text",
        strings_already_enriched=False,
        scan_strings_func=lambda blob, path: HostileSequence(("string_tag",)),
        artifact_read_snapshot=artifact_read_snapshot_fixture(path),
        attack_repository_digest=scan_session_snapshot_fixture().cache_execution_identity.attack_repository_digest,
    )

    assert "string_tag" in facts.tags


def test_stage1495_build_detection_api_context_detaches_hostile_enrichment_contexts(tmp_path):
    path = str(tmp_path / "game.rpy")

    def api_graph_enricher(*args, **kwargs):
        return HostileMapping({
            "api_calls": HostileSequence(("os.system",)),
            "sequence": HostileSequence(("api:os.system",)),
        })

    facts = build_detection_api_context(
        path=path, tags=HostileSequence(("renpy_script",)),
        strings_blob="call os.system", strings_already_enriched=True,
        failure_evidence=HostileSequence(({"input_failure": True},)),
        api_graph_enricher=api_graph_enricher,
        family_heuristics_builder=lambda **kwargs: {"score": 0.0, "hits": []},
    )

    assert facts.ordered_events == ("api_call",)
    assert facts.api_result["api_calls"] == ("os.system",)
    assert any(record.get("input_failure") for record in facts.failure_evidence if isinstance(record, Mapping))

