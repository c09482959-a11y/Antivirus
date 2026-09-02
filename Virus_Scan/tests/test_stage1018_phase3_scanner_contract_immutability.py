from __future__ import annotations

import pytest

from Virus_Scan.scanners.contracts.binary_result import BinaryAnalysisResult
from Virus_Scan.scanners.contracts.payload_result import PayloadDecodeResult


def test_binary_analysis_result_freezes_caller_owned_failure_evidence():
    evidence = {"scanner_name": "binary", "nested": {"items": ["a"]}}

    result = BinaryAnalysisResult("binary", "stage", False, False, ("x",), (evidence,), "boom")
    evidence["scanner_name"] = "mutated"
    evidence["nested"]["items"].append("mutated")

    assert result.failure_evidence[0]["scanner_name"] == "binary"
    assert result.failure_evidence[0]["nested"]["items"] == ("a",)
    with pytest.raises(TypeError):
        result.failure_evidence[0]["scanner_name"] = "changed"

    metadata = result.to_metadata()
    metadata["scanner_failure_evidence"][0]["scanner_name"] = "changed"
    assert result.failure_evidence[0]["scanner_name"] == "binary"


def test_payload_decode_result_freezes_caller_owned_failure_evidence():
    evidence = {"scanner_name": "payload", "decode_chain": ["base64"]}

    result = PayloadDecodeResult("base64", b"", False, ("payload_decode_failed",), (evidence,), "bad")
    evidence["scanner_name"] = "mutated"
    evidence["decode_chain"].append("mutated")

    assert result.failure_evidence[0]["scanner_name"] == "payload"
    assert result.failure_evidence[0]["decode_chain"] == ("base64",)
    with pytest.raises(TypeError):
        result.failure_evidence[0]["scanner_name"] = "changed"

    record = result.to_failure_record(depth=1)
    record["failure_evidence"][0]["scanner_name"] = "changed"
    assert result.failure_evidence[0]["scanner_name"] == "payload"


from Virus_Scan.scanners.config.error_contracts import ScannerConfigFailure


def test_scanner_config_failure_freezes_caller_owned_evidence():
    evidence = {"config_name": "payload_policy", "details": {"errors": ["missing"]}}

    failure = ScannerConfigFailure("payload_policy", "policy.json", "bad", (evidence,))
    evidence["config_name"] = "mutated"
    evidence["details"]["errors"].append("mutated")

    assert failure.failure_evidence[0]["config_name"] == "payload_policy"
    assert failure.failure_evidence[0]["details"]["errors"] == ("missing",)
    with pytest.raises(TypeError):
        failure.failure_evidence[0]["config_name"] = "changed"


from Virus_Scan.runtime.immutable_core import ImmutableRuntimeState, RuntimeStateReducer, RuntimeTransition
from Virus_Scan.scanners.config.binary_contracts import BinaryPolicySnapshot


def test_runtime_immutable_state_freezes_values_and_history():
    state = ImmutableRuntimeState(values={"a": {"items": ["x"]}}, history=({"event": {"tags": ["a"]}},))

    assert state.values["a"]["items"] == ("x",)
    assert state.history[0]["event"]["tags"] == ("a",)
    with pytest.raises(TypeError):
        state.values["a"] = "changed"
    with pytest.raises(TypeError):
        state.history[0]["event"] = "changed"


def test_runtime_reducer_history_is_not_mutable_caller_state():
    reducer = RuntimeStateReducer(owner="runtime")
    payload = {"item": ["original"]}
    state = reducer.apply(RuntimeTransition(owner="runtime", action="set", key="k", value=payload))
    payload["item"].append("mutated")

    assert state.values["k"]["item"] == ["original"] or state.values["k"]["item"] == ("original",)
    with pytest.raises(TypeError):
        state.history[0]["value"] = "changed"


def test_binary_policy_snapshot_freezes_nested_policy_tables():
    chain = {"name": "lolbin", "tags": ["exec"]}
    ransomware = {"families": ["ransom"]}
    bucket = {"bucket": {"terms": ["cmd"]}}
    snapshot = BinaryPolicySnapshot(
        entropy_read_max_bytes=4096, entropy_high_threshold=7.0, entropy_high_score=1.0,
        entropy_very_high_threshold=7.5, entropy_very_high_score=2.0,
        entropy_low_visibility_threshold=3.0, entropy_low_visibility_printable_ratio=0.5,
        entropy_low_visibility_score=1.0, entropy_packer_markers=("upx",), entropy_packer_score=1.0,
        dotnet_read_max_bytes=4096, dotnet_extensions=frozenset({".dll"}),
        dotnet_extension_mismatch_extensions=frozenset({".txt"}), dotnet_metadata_markers=("clr",),
        dotnet_behavior_markers=(("tag", "needle"),), il_opcode_patterns=(("op", "pattern"),),
        il_obfuscation_markers=("obf",), il_behavior_tag_weights={"exec": 1.0},
        il_score_call_ldstr_bonus=1.0, il_score_process_call_bonus=1.0, il_score_network_call_bonus=1.0,
        il_score_memory_pinvoke_bonus=1.0, il_obfuscation_per_marker=1.0, il_obfuscation_packed_bonus=1.0,
        il_obfuscation_indirect_call_bonus=1.0, il_op_score_weight=1.0, il_max_ops_for_score=10,
        il_obfuscation_marker_result_limit=10, dotnet_il_op_limit=10, dotnet_il_obfuscation_threshold=1.0,
        dotnet_il_behavior_threshold=1.0, binary_lolbin_chain_definitions=(chain,),
        binary_scheduled_task_persistence_rules=(chain,), binary_command_execution_terms=("cmd",),
        binary_c2_tasking_terms=("http",), binary_ransomware_terms=ransomware,
        binary_os_execution_tags=frozenset({"exec"}), binary_behavior_bucket_terms=bucket,
        binary_high_confidence_tags=frozenset({"high"}), raw_escalation_dangerous_anchor_tags=frozenset({"anchor"}),
        strict_fast_benign_extensions=frozenset({".txt"}), strict_fast_benign_max_bytes=100,
        strict_fast_benign_binary_magic=(b"MZ",), strict_fast_benign_deny_tokens=("bad",),
        binary_string_rules=(("tag", "needle"),), source="test",
        native_elf_import_semantics=(("read", "file_read"),),
        native_elf_syscall_semantics=((0, "read", "file_read"),),
    )
    chain["tags"].append("mutated")
    ransomware["families"].append("mutated")
    bucket["bucket"]["terms"].append("mutated")

    assert snapshot.binary_lolbin_chain_definitions[0]["tags"] == ("exec",)
    assert snapshot.binary_ransomware_terms["families"] == ("ransom",)
    assert snapshot.binary_behavior_bucket_terms["bucket"]["terms"] == ("cmd",)
    with pytest.raises(TypeError):
        snapshot.binary_lolbin_chain_definitions[0]["name"] = "changed"
