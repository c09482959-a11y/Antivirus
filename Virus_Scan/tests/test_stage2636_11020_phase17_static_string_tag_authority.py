from __future__ import annotations

from Virus_Scan.contracts.detection_observation import artifact_observations_for_path_tags
from Virus_Scan.contracts.tag_taxonomy import (
    TAG_CONTEXT_ONLY_MODALITIES,
    TAG_TAXONOMY_VERSION,
)
from Virus_Scan.detection.enrichment.strings.contextual.scan import (
    ContextualTagScanRequest,
    contextual_tag_scan,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.registries.tag_taxonomy_registry import (
    TAG_TAXONOMY_DIGEST,
    tag_taxonomy_manifest,
)
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_evidence, scoreable_tag_set
from Virus_Scan.detection.tags.heuristics.behavior_derivation import derive_behavior_evidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def _bundle(tags: list[str], *, modality: str) -> TagEvidence:
    observations = artifact_observations_for_path_tags(
        tags,
        producer_id="phase17_test",
        stage_id="tag_authority",
        path="sample.py",
        strings_blob="phase17 fixed content",
        modality=modality,
        integrity_status="verified",
    )
    return normalize_tag_evidence(
        observations,
        source_detector="phase17_test",
        source_stage="tag_authority",
        derive=True,
    )


def test_phase17_static_string_is_canonical_context_only_modality() -> None:
    manifest = tag_taxonomy_manifest()

    assert TAG_TAXONOMY_VERSION == "stage2636_11020_tag_taxonomy_v4"
    assert TAG_CONTEXT_ONLY_MODALITIES == frozenset({"static_string"})
    assert manifest["context_only_modalities"] == ("static_string",)
    assert manifest["digest"] == TAG_TAXONOMY_DIGEST
    assert len(TAG_TAXONOMY_DIGEST) == 64


def test_phase17_atomic_named_static_string_findings_are_preserved_but_cannot_score() -> None:
    tags = [
        "powershell_exec",
        "memory_write",
        "memory_protect",
        "thread_execution",
        "token_secret_access",
        "network_download",
    ]
    bundle = _bundle(tags, modality="static_string")

    assert set(tags) <= set(bundle.tags)
    observed = tuple(record for record in bundle.records if record.evidence_kind == "observed")
    assert {record.canonical_tag_id for record in observed} == set(tags)
    assert all(record.modality == "static_string" for record in observed)
    assert all(record.directness == "context" for record in observed)
    assert all(record.scoreability_class == "support" for record in observed)
    assert all(record.correlation_group == "" for record in observed)
    assert scoreable_tag_set(bundle) == set()


def test_phase17_static_string_atomic_names_cannot_mint_behavior_derivations() -> None:
    lexical = _bundle(
        ["memory_write", "memory_protect", "thread_execution"],
        modality="static_string",
    )
    derived = TagEvidence.from_records(derive_behavior_evidence(lexical.records))

    assert "process_injection" not in derived.tags
    assert all(record.directness != "direct" for record in lexical.records)


def test_phase17_nonlexical_atomic_observation_authority_is_unchanged() -> None:
    structured = _bundle(["powershell_exec"], modality="static_structure")
    record = next(record for record in structured.records if record.canonical_tag_id == "powershell_exec")

    assert record.modality == "static_structure"
    assert record.directness == "direct"
    assert record.scoreability_class == "scoreable"
    assert scoreable_tag_set(structured) == {"powershell_exec"}


def test_phase17_contextual_detection_vocabulary_is_preserved_for_existing_fixtures() -> None:
    fixtures = {
        "encoded_powershell": (
            "powershell -enc QUJDREVGR0g=",
            "game/evil.rpy",
            {
                "encoded_powershell", "powershell_exec", "process_exec",
                "payload_execution", "encoded_payload",
            },
        ),
        "native_injection": (
            "[DllImport('kernel32')] VirtualAllocEx(); WriteProcessMemory(); CreateRemoteThread(); UnityEngine;",
            "Assets/Scripts/NativeInject.cs",
            {
                "memory_allocate", "memory_write", "thread_execution",
                "process_injection", "in_memory_execution", "shellcode_exec",
            },
        ),
        "credential_exfil": (
            "discord token authorization access_token Login Data requests.post('https://example.invalid/webhook')",
            "game/token_stealer.rpy",
            {
                "token_secret_access", "token_exfiltration", "credential_access",
                "high_confidence_credential_theft",
            },
        ),
        "benign_doc": (
            "documentation mentions VirtualAllocEx WriteProcessMemory CreateRemoteThread but does not call them",
            "docs/readme.txt",
            {
                "memory_allocate", "memory_write", "thread_execution",
                "process_injection", "in_memory_execution", "shellcode_exec",
            },
        ),
    }
    for source, path, required in fixtures.values():
        tags = set(contextual_tag_scan(ContextualTagScanRequest(
            source, path=path, source="phase17_preservation",
        )))
        assert required <= tags


def test_phase17_documentation_only_injection_terms_remain_visible_but_zero_atomic_authority() -> None:
    text = "documentation mentions VirtualAllocEx WriteProcessMemory CreateRemoteThread but does not call them"
    tags = list(contextual_tag_scan(ContextualTagScanRequest(
        text, path="docs/readme.txt", source="phase17_preservation",
    )))
    bundle = _bundle(tags, modality="static_string")

    assert {"memory_write", "thread_execution", "process_injection"} <= set(bundle.tags)
    by_tag = {record.canonical_tag_id: record for record in bundle.records if record.evidence_kind == "observed"}
    assert by_tag["memory_write"].directness == "context"
    assert by_tag["thread_execution"].directness == "context"
    assert by_tag["process_injection"].directness == "context"
    assert by_tag["memory_write"].scoreability_class == "support"
    assert by_tag["thread_execution"].scoreability_class == "support"
    assert scoreable_tag_set(bundle) == set()


def test_phase17_scoreability_owner_never_mints_new_tag_evidence() -> None:
    source = physical_tag_evidence((
        "http_upload", "collection", "credential_access",
        "schtasks_create", "remote_scheduled_task",
    ), source_detector="phase17_scoreability")
    projected = scoreable_tag_evidence(
        source, allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )

    assert projected.records == source.records
    assert projected.reasons["scoreability_policy_version"] == "tag_scoreability_policy_v2_evidence_owned"
    assert not any(record.source_detector == "scoreable_tags" and record.evidence_kind == "derived" for record in projected.records)
    assert "network_download" not in projected.tags
    assert "scheduled_task" not in projected.tags


def test_phase17_bare_tag_names_have_no_physical_scoreability_authority() -> None:
    assert scoreable_tag_set(["cmd_exec", "encoded_payload", "http_upload"]) == set()
