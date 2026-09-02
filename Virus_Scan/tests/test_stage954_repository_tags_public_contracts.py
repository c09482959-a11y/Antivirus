
"""Stage 954 repository-wide test-audit coverage for root tag contracts.

These tests lock package-level tag behavior after inspecting ``Virus_Scan/tags.py``
and the detection-owned implementations it re-exports. They avoid production
changes and assert public behavior that was previously under-covered at the
repository root entrypoint.
"""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

import Virus_Scan.tags as root_tags
from Virus_Scan.detection.contracts import tag_validation
from Virus_Scan.contracts import tag_evidence as evidence_policy
from Virus_Scan.detection.scoring.weighting import scoreable_tags
from Virus_Scan.detection.scoring.weighting import tag_audit
from Virus_Scan.detection.tags.heuristics import behavior_derivation
from Virus_Scan.detection.tags.heuristics import behavior_mapping
from Virus_Scan.detection.tags import evidence_generation
from Virus_Scan.detection.tags.heuristics import primary_behavior
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def test_stage954_root_tags_is_static_public_alias_surface() -> None:
    """The root tag entrypoint remains a static alias, not a second owner."""
    source = read_python_file(Path("Virus_Scan/tags.py"))
    module = ast.parse(source, filename="Virus_Scan/tags.py")

    for node in ast.walk(module):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            assert node in module.body, f"function-scope import in root tags at line {node.lineno}"
        if isinstance(node, ast.Call):
            called = node.func
            assert not (
                isinstance(called, ast.Name) and called.id == "__import__"
            ), f"dynamic __import__ call in root tags at line {node.lineno}"
            assert not (
                isinstance(called, ast.Attribute)
                and isinstance(called.value, ast.Name)
                and called.value.id == "importlib"
            ), f"importlib runtime load in root tags at line {node.lineno}"

    expected_aliases = {
        "audit_tag_can_score": tag_audit.audit_tag_can_score,
        "audit_tag_class": tag_audit.audit_tag_class,
        "concrete_score_count": scoreable_tags.concrete_score_count,
        "derive_behavior_tags": behavior_derivation.derive_behavior_tags,
        "evidence_level_for_tag": evidence_policy.evidence_level_for_tag,
        "finalize_tag_evidence_generation": evidence_generation.finalize_tag_evidence_generation,
        "primary_behavior_for_tag": primary_behavior.primary_behavior_for_tag,
        "scoreable_tag_set": scoreable_tags.scoreable_tag_set,
        "tag_expected_behavior_mapping": behavior_mapping.tag_expected_behavior_mapping,
        "validate_tags_for_path": tag_validation.validate_tags_for_path,
    }
    assert expected_aliases.keys() <= set(root_tags.__all__)
    for name, canonical in expected_aliases.items():
        assert getattr(root_tags, name) is canonical


def test_stage954_root_tags_preserve_scoreable_and_mapping_behavior() -> None:
    """Root tag scoring helpers publish canonical detection behavior."""
    assert root_tags.audit_tag_class("cmd_exec") == "behavior"
    assert root_tags.audit_tag_class("pickle_global_reduce_chain") == "chain_projection"
    assert root_tags.audit_tag_class("file_seen") == "unknown"

    mapping = root_tags.tag_expected_behavior_mapping("remote_payload_download")
    assert mapping["tag"] == "remote_payload_download"
    assert mapping["role"] == "behavior"
    assert mapping["bucket"] == "network_download"
    assert mapping["timeline_use"] is True
    assert mapping["chain_use"] is True
    assert mapping["scoreable_without_chain"] is True

    unknown = root_tags.tag_expected_behavior_mapping("file_seen")
    assert unknown["role"] == "unknown"
    assert unknown["scoreable_without_chain"] is False

    canonical_evidence = physical_tag_evidence(
        ("file_seen", "cmd_exec", "encoded_payload", "payload_decode_candidate", "process_exec"),
        source_detector="stage954",
    )
    scoreable = root_tags.scoreable_tag_set(canonical_evidence)
    assert scoreable == {"cmd_exec", "encoded_payload"}
    assert root_tags.scoreable_tag_set(list(canonical_evidence.tags)) == set()
    assert {"process_exec", "payload_decode", "script_execution"}.isdisjoint(scoreable)
    assert "file_seen" not in scoreable
    assert root_tags.concrete_score_count(physical_tag_evidence(("memory_write", "memory_protect", "thread_execution"), source_detector="stage954")) == 3


def test_stage954_root_tags_derive_and_finalize_concrete_behavior_chains() -> None:
    """Validated concrete anchors derive stable higher-level behavior tags."""
    derived = root_tags.derive_behavior_tags(
        [
            "wmi_exec",
            "http_upload",
            "credential_dump_attempt",
            "memory_write",
            "memory_protect",
            "thread_execution",
        ]
    )
    assert {
        "lateral_movement",
        "remote_execution",
        "credential_access",
        "network_exfiltration",
        "process_injection",
    } <= set(derived)

    finalized = root_tags.finalize_tag_evidence_generation(
        ["memory_write", "memory_protect", "thread_execution"],
        path="sample.bin",
        strings_blob="WriteProcessMemory VirtualProtect CreateRemoteThread",
    ).evidence.tags
    assert {"memory_write", "memory_protect", "thread_execution"} <= set(finalized)
    assert "process_injection" not in finalized
    assert root_tags.primary_behavior_for_tag("process_injection") == "process_injection"


def test_stage954_root_tags_validation_preserves_confirmed_renpy_pickle_evidence() -> None:
    """Ren'Py bytecode pickle evidence remains visible after validation."""
    validated = root_tags.validate_tags_for_path(
        [
            "pickle_opcode_graph_analyzed",
            "pickle_reduce_opcode",
            "pickle_global_reference",
            "pickle_dangerous_global",
            "pickle_callable_reference",
            "process_exec",
        ],
        path="game/script.rpyc",
        strings_blob="pickletools GLOBAL REDUCE os.system subprocess.Popen CreateProcess",
    )
    assert {
        "pickle_opcode_graph_analyzed",
        "pickle_reduce_opcode",
        "pickle_global_reference",
        "pickle_dangerous_global",
        "pickle_callable_reference",
        "process_exec",
    } <= set(validated)
    assert "confirmed_pickle_exec_chain" not in validated

    level, confidence = root_tags.evidence_level_for_tag(
        "process_exec",
        strings_blob="subprocess.Popen os.system CreateProcess",
    )
    assert level == "reachable_exec"
    assert confidence >= 0.75
