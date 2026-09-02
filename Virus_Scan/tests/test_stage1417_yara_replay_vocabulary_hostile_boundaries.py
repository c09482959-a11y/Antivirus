
"""Stage 1417: remaining tag/YARA/replay model boundaries absorb hostile inputs."""

from __future__ import annotations
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.detection.scoring.yara.context_evidence import generic_yara_evidence_context
from Virus_Scan.detection.tags.heuristics.vocabulary import (
    canonical_raw_tag_list,
    canonical_raw_tag_name,
    canonical_tag_name,
    canonicalize_event_token,
)
from Virus_Scan.models.replay.transaction_projection import project_runtime_transaction_stats
from Virus_Scan.tests.support.profile_learning import (
    accepted_learning_request,
    accepted_runtime_transaction_result,
)


class HostileText:
    def __str__(self):  # pragma: no cover - exercised by boundary code
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


class HostileMidIteration:
    def __iter__(self):
        yield "process_exec"
        raise RuntimeError("hostile iteration tail")


class HostileMapping(dict):
    def __bool__(self):  # pragma: no cover
        raise RuntimeError("hostile bool")


def test_stage1417_tag_vocabulary_public_helpers_bound_hostile_text_and_iterables() -> None:
    assert canonical_tag_name(HostileText()) == "tag_normalization_failure_evidence"
    assert canonical_raw_tag_name(HostileText()) == "tag_normalization_failure_evidence"
    assert canonicalize_event_token(HostileText()) == "tag_normalization_failure_evidence"

    raw = canonical_raw_tag_list(HostileIterable())
    assert raw == ["tag_normalization_failure_evidence"]

    mixed = canonical_raw_tag_list(HostileMidIteration())
    assert "process_exec" not in mixed
    assert "tag_normalization_failure_evidence" in mixed


def test_stage1417_yara_context_rejects_hostile_input_without_hooks() -> None:
    context = generic_yara_evidence_context(HostileIterable())
    assert context.scan_status == "unavailable"
    assert context.root_observation_ids == ()
    assert context.probability_authority is False
    assert context.probability_unavailable_reason == "yara_scan_result_invalid"


def test_stage1417_parent_replay_transaction_projection_rejects_hostile_target_output(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"sample")
    request = accepted_learning_request(sample, flow=("decode", "execute"))
    learning_result = accepted_runtime_transaction_result(request)
    target_outputs = dict(learning_result["target_outputs"])
    target_outputs["markov"] = HostileIterable()
    learning_result["target_outputs"] = target_outputs

    summary = {"runtime": 0}
    stats = project_runtime_transaction_stats(learning_result, summary)

    assert stats["runtime_committed"] is False
    assert stats["reason"] == "runtime_target_output_unavailable:markov"
    assert stats["model_updates_authorized"] is True
    assert summary["runtime"] == 0

    non_mapping = project_runtime_transaction_stats(HostileText(), {"runtime": 0})
    assert non_mapping["runtime_committed"] is False
    assert non_mapping["reason"] == "learning_result_unavailable"

from Virus_Scan.detection.scoring.escalation.anchor_floors import apply_anchor_score_floors


def test_stage1417_anchor_floors_bound_hostile_stage_tags_and_api_calls() -> None:
    score, hits = apply_anchor_score_floors(
        HostileText(),
        evaluate_chain_evidence(),
        tags=HostileMidIteration(),
        stage=HostileText(),
    )

    assert score >= 0.0
    assert isinstance(hits, list)


def test_stage1417_anchor_floor_source_removes_raw_coercion_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/detection/scoring/escalation/anchor_floors.py"))
    tree = ast.parse(source)
    forbidden = (
        "return 0.0",
        'return ""',
        "return (safe_clamp(score_value, 0.0, 100.0), hits)",
    )
    assert [snippet for snippet in forbidden if snippet in source] == []
    assert [node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
