from pathlib import Path

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.chains.execution.syscall_sequence import detect_syscall_sequence_model
from Virus_Scan.detection.scoring.escalation.high_gate import (
    apply_anchor_chain_high_gate,
    high_gate_authority,
)
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


class HostileBoolIterable:
    bool_calls = 0
    iter_calls = 0

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("hostile bool must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("hostile iter must not execute")


class HostileText:
    str_calls = 0
    repr_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("hostile str must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("hostile repr must not execute")


class HostileFloat:
    bool_calls = 0
    float_calls = 0

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("hostile score bool must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("hostile score float must not execute")


def _reset_hostile_counters():
    HostileBoolIterable.bool_calls = 0
    HostileBoolIterable.iter_calls = 0
    HostileText.str_calls = 0
    HostileText.repr_calls = 0
    HostileFloat.bool_calls = 0
    HostileFloat.float_calls = 0


def _assert_no_hostile_hooks():
    assert HostileBoolIterable.bool_calls == 0
    assert HostileBoolIterable.iter_calls == 0
    assert HostileText.str_calls == 0
    assert HostileText.repr_calls == 0
    assert HostileFloat.bool_calls == 0
    assert HostileFloat.float_calls == 0


def test_high_gate_authority_rejects_hostile_tags_without_hooks():
    _reset_hostile_counters()
    info = high_gate_authority(
        evaluate_chain_evidence(),
        tags=HostileBoolIterable(),
    )
    assert info["allowed_high"] is False
    assert info["degraded"] is True
    _assert_no_hostile_hooks()


def test_apply_anchor_chain_high_gate_rejects_hostile_score_without_bool_or_float():
    _reset_hostile_counters()
    score, info = apply_anchor_chain_high_gate(
        HostileFloat(),
        evaluate_chain_evidence(),
        tags=HostileBoolIterable(),
    )
    assert score == 0.0
    assert info["degraded"] is True
    assert info["score_materialization_failure"] == "anchor_chain_high_gate_score_rejected"
    _assert_no_hostile_hooks()


def test_syscall_sequence_rejects_hostile_tags_and_blob_without_hooks():
    _reset_hostile_counters()
    result = detect_syscall_sequence_model(HostileText(), tags=HostileBoolIterable())
    assert result["score"] == 0.0
    assert "detection_stage_degraded" in result["tags"]
    assert "syscall_sequence_input_unavailable" in result["tags"]
    assert any(hit.startswith("syscall_sequence_input_unavailable:") for hit in result["hits"])
    _assert_no_hostile_hooks()


def test_high_gate_and_syscall_valid_behavior_is_preserved():
    atomic_tags = ("pickle_reduce_opcode", "pickle_callable_reference")
    chain_evidence = evaluate_chain_evidence(
        tags=physical_tag_evidence(
            atomic_tags,
            correlation_group="pickle_execution",
            source_detector="stage1774_pickle_fixture",
            source_stage="pickle_physical_evidence",
        )
    )
    allowed = high_gate_authority(chain_evidence, tags=atomic_tags)
    assert allowed["allowed_high"] is True
    assert allowed["single_anchors"] == ()
    assert "anchor:pickle_execution_anchor" in allowed["explicit_behavior_anchors"]

    score, info = apply_anchor_chain_high_gate(
        80.0, evaluate_chain_evidence(), tags=(),
    )
    assert score < 80.0
    assert info["cap_applied"] is True

    syscall = detect_syscall_sequence_model("VirtualAlloc WriteProcessMemory CreateRemoteThread", tags=("process_injection",))
    assert syscall["chain_count"] == 3
    assert "shellcode_loader" in syscall["tags"]
    assert syscall["score"] > 0.0


def test_high_gate_and_syscall_sources_do_not_retain_raw_hookable_coercions():
    sources = {
        Path("Virus_Scan/detection/scoring/escalation/high_gate.py"): (
            "tags or []",
            "api_calls or []",
            "ordered_events or []",
            "str(hit or '')",
            "float(score or 0.0)",
            "float(explicit_meta.get('floor') or 0.0)",
        ),
        Path("Virus_Scan/detection/chains/execution/syscall_sequence.py"): (
            "set(tags or [])",
            "str(strings_blob or '')",
        ),
    }
    for path, forbidden_values in sources.items():
        source = path.read_text(encoding="utf-8")
        for forbidden in forbidden_values:
            assert forbidden not in source
