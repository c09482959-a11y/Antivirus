"""Stage2636.10011 Phase 5 atomic tag taxonomy and alignment contracts."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from Virus_Scan.contracts.tag_taxonomy import (
    TAG_CLASS_ATOMIC_OBSERVATION,
    TAG_CLASS_BEHAVIOR_DERIVATION,
    TAG_CLASS_REPORTING_ONLY,
    TagDefinition,
)
from Virus_Scan.detection.attack.alignment import (
    TAG_STIX_ALIGNMENT_BY_TAG,
    TAG_STIX_ALIGNMENT_SPECS,
    TagStixAlignmentSpec,
    active_tag_stix_alignments,
    tag_stix_alignment_manifest,
)
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICIES
from Virus_Scan.detection.registries.tag_taxonomy_registry import (
    TAG_DEFINITIONS,
    TAG_DEFINITION_BY_ID,
    TAG_TAXONOMY_DIGEST,
    tag_class_for,
    tag_taxonomy_manifest,
)
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


class _StringSubclass(str):
    pass


def test_all_declared_tags_have_one_exact_immutable_class() -> None:
    assert len(TAG_DEFINITIONS) == len(TAG_DEFINITION_BY_ID)
    assert tuple(item.tag_id for item in TAG_DEFINITIONS) == tuple(
        sorted(TAG_DEFINITION_BY_ID)
    )
    assert tag_taxonomy_manifest()["definition_count"] == len(TAG_DEFINITIONS)
    with pytest.raises(TypeError):
        TagDefinition(_StringSubclass("powershell_exec"), TAG_CLASS_ATOMIC_OBSERVATION)


def test_broad_reporting_and_behavior_terms_are_not_atomic() -> None:
    expected = {
        "credential_access": TAG_CLASS_BEHAVIOR_DERIVATION,
        "defense_evasion": TAG_CLASS_BEHAVIOR_DERIVATION,
        "lateral_movement": TAG_CLASS_BEHAVIOR_DERIVATION,
        "network_exfiltration": TAG_CLASS_BEHAVIOR_DERIVATION,
        "process_injection": TAG_CLASS_BEHAVIOR_DERIVATION,
        "script_execution": TAG_CLASS_BEHAVIOR_DERIVATION,
        "credential_dumping": TAG_CLASS_REPORTING_ONLY,
        "disable_security_tools": TAG_CLASS_REPORTING_ONLY,
    }
    assert {tag: tag_class_for(tag) for tag in expected} == expected


def test_technique_policy_has_no_direct_tag_or_broad_mapping_authority() -> None:
    assert ATTACK_TECHNIQUE_POLICIES
    assert all(not hasattr(policy, "tag_ids") for policy in ATTACK_TECHNIQUE_POLICIES)
    assert set(TAG_STIX_ALIGNMENT_BY_TAG)
    assert all(
        tag_class_for(tag) == TAG_CLASS_ATOMIC_OBSERVATION
        for tag in TAG_STIX_ALIGNMENT_BY_TAG
    )


def test_unreviewed_and_context_only_bindings_are_nonactive_and_unbound() -> None:
    assert TAG_STIX_ALIGNMENT_SPECS
    assert active_tag_stix_alignments() == ()
    unmapped = tuple(
        item for item in TAG_STIX_ALIGNMENT_SPECS
        if item.alignment_state == "unmapped"
    )
    context_only = tuple(
        item for item in TAG_STIX_ALIGNMENT_SPECS
        if item.alignment_state == "context_only"
    )
    assert len(unmapped) == 36
    assert len(context_only) == 7
    assert all(item.dataset_requirement_digest == "" for item in TAG_STIX_ALIGNMENT_SPECS)
    assert all(item.data_component_ids == () for item in context_only)
    assert all(item.supported_modalities == ("static_control_flow",) for item in context_only)
    assert all(item.supported_platforms == ("windows",) for item in context_only)
    assert all(item.producer_ids == ("python_renpy_static_analysis",) for item in context_only)
    manifest = tag_stix_alignment_manifest()
    assert manifest["alignment_count"] == 43
    assert manifest["active_alignment_count"] == 0
    assert len(manifest["digest"]) == 64


def test_active_alignment_requires_atomic_tag_complete_fields_and_digest() -> None:
    spec = TagStixAlignmentSpec(
        "powershell_exec", ("DC0001",), ("static_string",), ("Windows",),
        ("artifact_identity", "integrity_status", "source_location"),
        ("full_analysis_string_scanner",), "partial", "a" * 64,
    )
    assert spec.alignment_state == "partial"
    with pytest.raises(ValueError, match="atomic_tag_required"):
        TagStixAlignmentSpec(
            "script_execution", ("DC0001",), ("static_string",), ("Windows",),
            ("artifact_identity",), ("producer",), "partial", "a" * 64,
        )
    with pytest.raises(ValueError, match="active_fields_required"):
        TagStixAlignmentSpec(
            "powershell_exec", (), ("static_string",), ("Windows",),
            ("artifact_identity",), ("producer",), "partial", "a" * 64,
        )


def test_aliases_from_one_observation_keep_one_root_and_no_new_independence() -> None:
    bundle = physical_tag_evidence(
        ("powershell_exec", "encoded_powershell"), one_root=True,
    )
    roots = {
        record.root_observation_id for record in bundle.records
        if record.canonical_tag_id in {"powershell_exec", "encoded_powershell"}
    }
    assert len(roots) == 1
    separate = physical_tag_evidence(("powershell_exec", "powershell_exec"))
    assert len({record.root_observation_id for record in separate.records}) == 2


def test_taxonomy_and_alignment_manifests_are_cross_process_deterministic() -> None:
    script = (
        "import json; "
        "from Virus_Scan.detection.registries.tag_taxonomy_registry import TAG_TAXONOMY_DIGEST; "
        "from Virus_Scan.detection.attack.alignment import tag_stix_alignment_manifest; "
        "print(json.dumps([TAG_TAXONOMY_DIGEST, tag_stix_alignment_manifest()['digest']]))"
    )
    first = subprocess.check_output([sys.executable, "-c", script], text=True, timeout=30).strip()
    second = subprocess.check_output([sys.executable, "-c", script], text=True, timeout=30).strip()
    assert first == second
    assert json.loads(first)[0] == TAG_TAXONOMY_DIGEST
