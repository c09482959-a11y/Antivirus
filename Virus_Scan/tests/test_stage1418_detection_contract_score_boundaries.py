from __future__ import annotations

from Virus_Scan.detection.chains.composite.attack_authority import has_concrete_attack_chain
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.contracts.progress import has_any_tag, stage_progress
from Virus_Scan.detection.contracts.string_extraction import (
    build_extraction_view,
    looks_like_base64_payload,
    normalize_obfuscated_text,
)
from Virus_Scan.detection.scoring.full_analysis.classification import (
    classify_detection_score,
    detection_exit_code_for_score,
)
from Virus_Scan.detection.scoring.weighting.concrete_attack_cap import apply_no_concrete_attack_cap


class HostileText:
    def __bool__(self):
        raise RuntimeError("truthiness unavailable")

    def __str__(self):
        raise RuntimeError("text unavailable")


class HostileInt:
    def __int__(self):
        raise RuntimeError("int unavailable")


class HostileFloat:
    def __bool__(self):
        raise RuntimeError("truthiness unavailable")

    def __float__(self):
        raise RuntimeError("score unavailable")


class HostileIterable:
    def __iter__(self):
        raise RuntimeError("iteration unavailable")

    def __bool__(self):
        raise RuntimeError("truthiness unavailable")


class HostileItem:
    def __str__(self):
        raise RuntimeError("item text unavailable")


def test_stage1418_string_extraction_hostile_inputs_emit_failure_evidence():
    assert looks_like_base64_payload(HostileText()) is False
    assert normalize_obfuscated_text(HostileText()) == "string_extraction_failure_evidence"

    view = build_extraction_view(HostileText(), path=HostileText(), decoded_payloads=[{"text": HostileText()}])

    assert "string_extraction_failure_evidence" in view


def test_stage1418_progress_contract_hostile_inputs_are_bounded():
    progress = stage_progress(HostileText(), inc=HostileInt(), bytes_delta=HostileInt())

    assert progress["stage"] == "scan"
    assert progress["inc"] == 0
    assert progress["bytes_delta"] == 0
    assert has_any_tag(HostileIterable(), "memory_write") is False
    assert has_any_tag([HostileItem(), "memory_write"], "memory_write") is True


def test_stage1418_malformed_score_does_not_become_clean_classification():
    assert classify_detection_score(HostileFloat()) == ("score_unavailable", 0.0)
    assert detection_exit_code_for_score(HostileFloat()) == 4


def test_stage1418_concrete_attack_chain_and_cap_handle_hostile_sequences():
    evidence = evaluate_chain_evidence(
        tags=HostileIterable(),
        api_calls=HostileIterable(),
        ordered_events=HostileIterable(),
    )
    assert has_concrete_attack_chain(evidence) is False

    capped, meta = apply_no_concrete_attack_cap(
        95.0, evidence, path="sample.exe",
    )

    assert capped == 60.0
    assert meta is not None
    assert meta["name"] == "no_concrete_attack_binary_cap"
