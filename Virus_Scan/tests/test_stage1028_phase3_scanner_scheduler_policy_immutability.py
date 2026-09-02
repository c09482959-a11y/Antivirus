from __future__ import annotations

import pytest

from Virus_Scan.scanners.ci.public_export_smoke_cases import PublicExportSmokeCaseContext
from Virus_Scan.scanners.config.archive_limits_contracts import ArchivePolicySnapshot
from Virus_Scan.scanners.config.binary_contracts import BinaryPolicySnapshot
from Virus_Scan.scheduler.orchestration.inmemory_parent_timeout_maintenance import InMemoryTimeoutMaintenanceResult


def test_stage1028_archive_policy_snapshot_normalizes_direct_constructor_collections() -> None:
    suffixes = [".zip"]
    snapshot = ArchivePolicySnapshot(
        default_max_depth="2",  # type: ignore[arg-type]
        default_max_members=True,  # type: ignore[arg-type]
        default_max_member_size=100,
        member_probe_bytes=10,
        member_text_max_size=20,
        ecosystem_score_limit=30,
        ecosystem_score_warn=40,
        rpa_read_max_bytes=50,
        rpa_index_max_bytes=60,
        rpa_member_max_bytes=70,
        rpa_member_max_count=80,
        rpa_zip_max_depth=90,
        rpa_zip_max_members=100,
        rpa_zip_max_member_size=110,
        nested_archive_suffixes=suffixes,  # type: ignore[arg-type]
        rarity_high_risk_probability="0.1",  # type: ignore[arg-type]
        rarity_high_risk_min_score=1,
        rarity_high_risk_multiplier=2,
        rarity_rare_probability=3,
        rarity_rare_multiplier=4,
        rarity_uncommon_probability=5,
        rarity_uncommon_multiplier=6,
        rarity_common_probability=7,
        rarity_common_multiplier=8,
        rarity_default_multiplier=9,
        source=123,  # type: ignore[arg-type]
        schema=None,  # type: ignore[arg-type]
    )
    suffixes.append(".mutated")

    assert snapshot.default_max_depth == 2
    assert snapshot.default_max_members == 1
    assert snapshot.nested_archive_suffixes == (".zip",)
    assert snapshot.rarity_high_risk_probability == 0.1
    assert snapshot.source == "123"
    assert snapshot.schema == "archive_policy.v1"
    with pytest.raises(AttributeError):
        snapshot.nested_archive_suffixes = ()  # type: ignore[misc]


def test_stage1028_binary_policy_snapshot_freezes_direct_constructor_sequence_inputs() -> None:
    packer_markers = ["upx"]
    dotnet_extensions = [".dll"]
    behavior_markers = [["exec", "Process.Start"]]
    magic = [b"MZ"]
    string_rules = [["exec", "cmd.exe"]]
    snapshot = BinaryPolicySnapshot(
        entropy_read_max_bytes="4096",  # type: ignore[arg-type]
        entropy_high_threshold="7.0",  # type: ignore[arg-type]
        entropy_high_score=1,
        entropy_very_high_threshold=7.5,
        entropy_very_high_score=2,
        entropy_low_visibility_threshold=3,
        entropy_low_visibility_printable_ratio=0.5,
        entropy_low_visibility_score=1,
        entropy_packer_markers=packer_markers,  # type: ignore[arg-type]
        entropy_packer_score=1,
        dotnet_read_max_bytes=4096,
        dotnet_extensions=dotnet_extensions,  # type: ignore[arg-type]
        dotnet_extension_mismatch_extensions=[".txt"],  # type: ignore[arg-type]
        dotnet_metadata_markers=["clr"],  # type: ignore[arg-type]
        dotnet_behavior_markers=behavior_markers,  # type: ignore[arg-type]
        il_opcode_patterns=[["call", "Process"]],  # type: ignore[arg-type]
        il_obfuscation_markers=["obf"],  # type: ignore[arg-type]
        il_behavior_tag_weights={"exec": 1.0},
        il_score_call_ldstr_bonus=1,
        il_score_process_call_bonus=1,
        il_score_network_call_bonus=1,
        il_score_memory_pinvoke_bonus=1,
        il_obfuscation_per_marker=1,
        il_obfuscation_packed_bonus=1,
        il_obfuscation_indirect_call_bonus=1,
        il_op_score_weight=1,
        il_max_ops_for_score=10,
        il_obfuscation_marker_result_limit=10,
        dotnet_il_op_limit=10,
        dotnet_il_obfuscation_threshold=1,
        dotnet_il_behavior_threshold=1,
        binary_lolbin_chain_definitions=({"name": "lolbin", "tags": ["exec"]},),
        binary_scheduled_task_persistence_rules=({"name": "task", "tags": ["persist"]},),
        binary_command_execution_terms=["cmd"],  # type: ignore[arg-type]
        binary_c2_tasking_terms=["http"],  # type: ignore[arg-type]
        binary_ransomware_terms={"families": ["ransom"]},
        binary_os_execution_tags=["exec"],  # type: ignore[arg-type]
        binary_behavior_bucket_terms={"bucket": {"terms": ["cmd"]}},
        binary_high_confidence_tags=["high"],  # type: ignore[arg-type]
        raw_escalation_dangerous_anchor_tags=["anchor"],  # type: ignore[arg-type]
        strict_fast_benign_extensions=[".txt"],  # type: ignore[arg-type]
        strict_fast_benign_max_bytes="100",  # type: ignore[arg-type]
        strict_fast_benign_binary_magic=magic,  # type: ignore[arg-type]
        strict_fast_benign_deny_tokens=["bad"],  # type: ignore[arg-type]
        binary_string_rules=string_rules,  # type: ignore[arg-type]
        native_elf_import_semantics=(("read", "file_read"),),
        native_elf_syscall_semantics=((0, "read", "file_read"),),
        source=456,  # type: ignore[arg-type]
        schema=None,  # type: ignore[arg-type]
    )
    packer_markers.append("mutated")
    dotnet_extensions.append(".mutated")
    behavior_markers[0][1] = "mutated"
    magic.append(b"PE")
    string_rules[0][1] = "mutated"

    assert snapshot.entropy_read_max_bytes == 4096
    assert snapshot.entropy_packer_markers == ("upx",)
    assert snapshot.dotnet_extensions == frozenset({".dll"})
    assert snapshot.dotnet_behavior_markers == (("exec", "Process.Start"),)
    assert snapshot.strict_fast_benign_binary_magic == (b"MZ",)
    assert snapshot.binary_string_rules == (("exec", "cmd.exe"),)
    assert snapshot.source == "456"
    assert snapshot.schema == "binary_policy.v1"
    with pytest.raises(AttributeError):
        snapshot.dotnet_extensions = frozenset()  # type: ignore[misc]


def test_stage1028_timeout_maintenance_result_freezes_caller_owned_evidence() -> None:
    evidence = {"job_id": "a", "details": {"tags": ["timeout"]}}
    result = InMemoryTimeoutMaintenanceResult(timeout_retry_evidence=(evidence,), timeout_reporting_failures=())
    evidence["job_id"] = "mutated"
    evidence["details"]["tags"].append("mutated")

    assert result.timeout_retry_evidence[0]["job_id"] == "a"
    assert result.timeout_retry_evidence[0]["details"]["tags"] == ("timeout",)
    with pytest.raises(TypeError):
        result.timeout_retry_evidence[0]["job_id"] = "changed"  # type: ignore[index]


def test_stage1028_public_export_smoke_context_freezes_chunk_kwargs() -> None:
    kwargs = {"nested": {"items": ["a"]}}
    ctx = PublicExportSmokeCaseContext(
        text_path=1,  # type: ignore[arg-type]
        binary_path=2,  # type: ignore[arg-type]
        image_path=3,  # type: ignore[arg-type]
        rpa_path=4,  # type: ignore[arg-type]
        zip_path=5,  # type: ignore[arg-type]
        text_blob=6,  # type: ignore[arg-type]
        bytes_blob=bytearray(b"x"),  # type: ignore[arg-type]
        chunk_kwargs=kwargs,
    )
    kwargs["nested"]["items"].append("mutated")

    assert ctx.text_path == "1"
    assert ctx.bytes_blob == b"x"
    assert ctx.chunk_kwargs["nested"]["items"] == frozenset({"a"})
    with pytest.raises(TypeError):
        ctx.chunk_kwargs["nested"] = {}  # type: ignore[index]

from Virus_Scan.detection.scoring.explainability.score_component_models import ScoreContribution
from Virus_Scan.scheduler.timeout.process_queue_stall_evidence import ProcessQueueStallEscalationEvidence


def test_stage1028_score_contribution_freezes_evidence_reference() -> None:
    refs = ["scanner:evidence"]
    contribution = ScoreContribution(
        score_source=1,  # type: ignore[arg-type]
        weight="2.5",  # type: ignore[arg-type]
        raw_score=3,
        weighted_score=4,
        evidence_reference=refs,  # type: ignore[arg-type]
        reason=5,  # type: ignore[arg-type]
        engine_context=6,  # type: ignore[arg-type]
        filetype_context=7,  # type: ignore[arg-type]
        confidence_impact=8,
        malicious_contribution=9,
        suspicious_contribution=10,
        benign_contribution=11,
    )
    refs.append("mutated")

    assert contribution.score_source == "1"
    assert contribution.weight == 2.5
    assert contribution.evidence_reference == ("scanner:evidence",)
    assert contribution.to_record()["evidence_reference"] == ["scanner:evidence"]
    with pytest.raises(AttributeError):
        contribution.evidence_reference = ()  # type: ignore[misc]


def test_stage1028_process_queue_stall_evidence_normalizes_direct_constructor_values() -> None:
    evidence = ProcessQueueStallEscalationEvidence(
        worker_idx=1,
        pid=2,
        action=None,  # type: ignore[arg-type]
        reason=None,  # type: ignore[arg-type]
        error_category=None,  # type: ignore[arg-type]
        error_source=None,  # type: ignore[arg-type]
        detail=123,  # type: ignore[arg-type]
        elapsed_sec="1.5",  # type: ignore[arg-type]
        final_json_must_record=1,  # type: ignore[arg-type]
        checkpoint_must_record=0,  # type: ignore[arg-type]
        replay_must_reproduce=True,
    )

    record = evidence.as_record()
    assert evidence.action == "stall_escalation"
    assert evidence.reason == "process_queue_progress_stalled"
    assert evidence.error_category == "RuntimeError"
    assert evidence.elapsed_sec == 1.5
    assert evidence.checkpoint_must_record is False
    assert record["detail"] == "123"
    with pytest.raises(AttributeError):
        evidence.elapsed_sec = 0.0  # type: ignore[misc]
