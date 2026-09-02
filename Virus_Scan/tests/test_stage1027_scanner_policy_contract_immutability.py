from __future__ import annotations

import pytest

from Virus_Scan.scanners.config.core_contracts import (
    PayloadPolicySnapshot,
    PicklePolicySnapshot,
    RawChunkPolicySnapshot,
)


def test_stage1027_payload_policy_snapshot_normalizes_direct_constructor_values() -> None:
    snapshot = PayloadPolicySnapshot(
        max_candidates="3",  # type: ignore[arg-type]
        max_text_bytes=True,  # type: ignore[arg-type]
        min_base64_chars=None,  # type: ignore[arg-type]
        min_hex_chars=4,
        default_max_depth="5",  # type: ignore[arg-type]
        source=123,  # type: ignore[arg-type]
        schema=None,  # type: ignore[arg-type]
    )

    assert snapshot.max_candidates == 3
    assert snapshot.max_text_bytes == 1
    assert snapshot.min_base64_chars == 0
    assert snapshot.min_hex_chars == 4
    assert snapshot.default_max_depth == 5
    assert snapshot.source == "123"
    assert snapshot.schema == "payload_policy.v1"
    with pytest.raises(AttributeError):
        snapshot.max_candidates = 9  # type: ignore[misc]


def test_stage1027_pickle_policy_snapshot_deep_freezes_collection_inputs() -> None:
    renpy_extensions = [".rpyc"]
    dangerous_globals = {"os.system"}
    exec_needles = ["exec"]
    snapshot = PicklePolicySnapshot(
        fast_escalation_max_bytes="10",  # type: ignore[arg-type]
        fast_b64_sample_max=20,
        renpy_extensions=renpy_extensions,  # type: ignore[arg-type]
        decode_max_decoded_bytes=30,
        decode_max_file_bytes=40,
        decode_max_objects=50,
        decode_max_offsets=60,
        decode_min_payload_bytes=70,
        fragment_min_b64_chars=80,
        literal_join_max=90,
        fast_dangerous_text=("danger",),
        fast_exec_text=("exec",),
        safe_reconstruct_globals={"copy_reg"},  # type: ignore[arg-type]
        safe_reconstruct_prefixes=["renpy."],  # type: ignore[arg-type]
        dangerous_globals=dangerous_globals,  # type: ignore[arg-type]
        suspicious_global_parts={"subprocess"},  # type: ignore[arg-type]
        decoded_payload_exec_needles=exec_needles,  # type: ignore[arg-type]
        decoded_payload_network_needles=["http"],  # type: ignore[arg-type]
        source=456,  # type: ignore[arg-type]
        schema=None,  # type: ignore[arg-type]
    )

    renpy_extensions.append(".mutated")
    dangerous_globals.add("mutated")
    exec_needles.append("mutated")

    assert snapshot.fast_escalation_max_bytes == 10
    assert snapshot.renpy_extensions == (".rpyc",)
    assert snapshot.dangerous_globals == frozenset({"os.system"})
    assert snapshot.decoded_payload_exec_needles == ("exec",)
    assert snapshot.source == "456"
    assert snapshot.schema == "pickle_policy.v1"
    with pytest.raises(AttributeError):
        snapshot.renpy_extensions = ()  # type: ignore[misc]


def test_stage1027_raw_chunk_policy_snapshot_deep_freezes_anchor_inputs() -> None:
    context = ["powershell"]
    decode = ["base64"]
    snapshot = RawChunkPolicySnapshot(context_anchors=context, decode_anchors=decode, source=789, schema=None)  # type: ignore[arg-type]

    context.append("mutated")
    decode.append("mutated")

    assert snapshot.context_anchors == ("powershell",)
    assert snapshot.decode_anchors == ("base64",)
    assert snapshot.source == "789"
    assert snapshot.schema == "raw_chunk_policy.v1"
    with pytest.raises(AttributeError):
        snapshot.context_anchors = ()  # type: ignore[misc]
