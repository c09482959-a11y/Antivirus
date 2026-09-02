"""Immutable reviewed STIX-to-local tag alignment policy owner."""
from __future__ import annotations

from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType

from Virus_Scan.contracts.tag_taxonomy import TAG_CLASS_ATOMIC_OBSERVATION
from Virus_Scan.detection.attack.validation import exact_hex, ordered_text_tuple
from Virus_Scan.detection.registries.tag_taxonomy_registry import tag_class_for

TAG_STIX_ALIGNMENT_VERSION = "stage2636_11020_tag_stix_alignment_v3"
ALIGNMENT_STATES = frozenset({"exact", "partial", "context_only", "unmapped"})
_ACTIVE_ALIGNMENT_STATES = frozenset({"exact", "partial"})
_ALLOWED_MODALITIES = frozenset({
    "static_string", "static_structure", "static_control_flow",
    "dynamic_runtime", "host_telemetry", "network_telemetry", "yara_match",
    "metadata", "derived",
})
_ALLOWED_FIELDS = frozenset({
    "actor_identity", "artifact_identity", "connection_identity", "directness",
    "host_identity", "integrity_status", "modality", "observation_id",
    "ordinal", "platform", "process_identity", "producer_id",
    "root_observation_id", "source_location", "stage_id", "target_identity",
    "timestamp", "timing_provenance",
})


@dataclass(frozen=True, slots=True)
class TagStixAlignmentSpec:
    tag_id: str
    data_component_ids: tuple[str, ...]
    supported_modalities: tuple[str, ...]
    supported_platforms: tuple[str, ...]
    required_observation_fields: tuple[str, ...]
    producer_ids: tuple[str, ...]
    alignment_state: str
    dataset_requirement_digest: str
    alignment_version: str = TAG_STIX_ALIGNMENT_VERSION

    def __post_init__(self) -> None:
        if type(self) is not TagStixAlignmentSpec:
            raise TypeError("tag_stix_alignment_owner_invalid")
        tag_id = exact_bounded_text(self.tag_id, "tag_stix_alignment_tag_invalid")
        data_components = ordered_text_tuple(
            self.data_component_ids, "tag_stix_alignment_components_invalid",
            maximum_items=32,
        )
        if any(not item.startswith("DC") or not item[2:].isdigit() for item in data_components):
            raise ValueError("tag_stix_alignment_components_invalid")
        modalities = ordered_text_tuple(
            self.supported_modalities, "tag_stix_alignment_modalities_invalid",
            maximum_items=16,
        )
        fields = ordered_text_tuple(
            self.required_observation_fields, "tag_stix_alignment_fields_invalid",
            maximum_items=32,
        )
        platforms = ordered_text_tuple(
            self.supported_platforms, "tag_stix_alignment_platforms_invalid",
            maximum_items=32,
        )
        producers = ordered_text_tuple(
            self.producer_ids, "tag_stix_alignment_producers_invalid",
            maximum_items=32,
        )
        state = exact_bounded_text(self.alignment_state, "tag_stix_alignment_state_invalid")
        if state not in ALIGNMENT_STATES:
            raise ValueError("tag_stix_alignment_state_invalid")
        if any(item not in _ALLOWED_MODALITIES for item in modalities):
            raise ValueError("tag_stix_alignment_modalities_invalid")
        if any(item not in _ALLOWED_FIELDS for item in fields):
            raise ValueError("tag_stix_alignment_fields_invalid")
        digest = self.dataset_requirement_digest
        if state in _ACTIVE_ALIGNMENT_STATES:
            if tag_class_for(tag_id) != TAG_CLASS_ATOMIC_OBSERVATION:
                raise ValueError("tag_stix_alignment_atomic_tag_required")
            if not data_components or not modalities or not platforms or not fields or not producers:
                raise ValueError("tag_stix_alignment_active_fields_required")
            digest = exact_hex(digest, "tag_stix_alignment_digest_invalid", length=64)
        elif type(digest) is not str or digest:
            raise ValueError("tag_stix_alignment_inactive_digest_invalid")
        object.__setattr__(self, "tag_id", tag_id)
        object.__setattr__(self, "data_component_ids", data_components)
        object.__setattr__(self, "supported_modalities", modalities)
        object.__setattr__(self, "supported_platforms", platforms)
        object.__setattr__(self, "required_observation_fields", fields)
        object.__setattr__(self, "producer_ids", producers)
        object.__setattr__(self, "alignment_state", state)
        object.__setattr__(self, "dataset_requirement_digest", digest)
        object.__setattr__(self, "alignment_version", exact_bounded_text(
            self.alignment_version, "tag_stix_alignment_version_invalid",
        ))

    def to_record(self) -> dict[str, object]:
        return {
            "tag_id": self.tag_id, "data_component_ids": self.data_component_ids,
            "supported_modalities": self.supported_modalities,
            "supported_platforms": self.supported_platforms,
            "required_observation_fields": self.required_observation_fields,
            "producer_ids": self.producer_ids, "alignment_state": self.alignment_state,
            "dataset_requirement_digest": self.dataset_requirement_digest,
            "alignment_version": self.alignment_version,
        }


_UNBOUND_TAGS = (
    "admin_share_access", "amsi_scanbuffer_patch", "browser_profile_access",
    "cmd_exec", "credential_dump_attempt", "cscript_exec", "defender_disable",
    "dns_tunneling", "dpapi_access", "encoded_powershell", "etw_eventwrite_patch",
    "http_upload", "lolbin_download", "lsass_access", "memory_allocate",
    "memory_protect", "memory_write", "mimikatz_credential_dump", "mshta_exec",
    "network_c2", "network_download", "powershell_exec", "process_hollowing",
    "psexec_usage", "rdp_enable_or_use", "remote_payload_download",
    "remote_registry", "remote_service_creation", "security_process_kill",
    "security_service_disable", "smb_activity", "tamper_protection_disable",
    "thread_execution", "token_secret_access",
    "winrm_exec", "wscript_exec",
)
_STATIC_CONTEXT_TAGS = (
    "static_create_remote_thread_operation",
    "static_encoded_powershell_launch_operation",
    "static_minidump_write_dump_operation",
    "static_open_process_operation",
    "static_virtual_alloc_ex_operation",
    "static_virtual_protect_ex_operation",
    "static_write_process_memory_operation",
)
_STATIC_CONTEXT_FIELDS = (
    "actor_identity",
    "artifact_identity",
    "directness",
    "integrity_status",
    "modality",
    "observation_id",
    "ordinal",
    "platform",
    "producer_id",
    "root_observation_id",
    "source_location",
    "stage_id",
    "target_identity",
    "timing_provenance",
)
TAG_STIX_ALIGNMENT_SPECS = (
    *(
        TagStixAlignmentSpec(tag_id, (), (), (), (), (), "unmapped", "")
        for tag_id in _UNBOUND_TAGS
    ),
    *(
        TagStixAlignmentSpec(
            tag_id,
            (),
            ("static_control_flow",),
            ("windows",),
            _STATIC_CONTEXT_FIELDS,
            ("python_renpy_static_analysis",),
            "context_only",
            "",
        )
        for tag_id in _STATIC_CONTEXT_TAGS
    ),
)
TAG_STIX_ALIGNMENT_BY_TAG = MappingProxyType({
    item.tag_id: item for item in TAG_STIX_ALIGNMENT_SPECS
})


def active_tag_stix_alignments() -> tuple[TagStixAlignmentSpec, ...]:
    return tuple(
        item for item in TAG_STIX_ALIGNMENT_SPECS
        if item.alignment_state in _ACTIVE_ALIGNMENT_STATES
    )


def active_attack_tag_ids() -> frozenset[str]:
    return frozenset(item.tag_id for item in active_tag_stix_alignments())


def tag_stix_alignment_manifest() -> dict[str, object]:
    records = tuple(item.to_record() for item in TAG_STIX_ALIGNMENT_SPECS)
    digest = hashlib.sha256(json.dumps(
        records, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()
    return {
        "version": TAG_STIX_ALIGNMENT_VERSION,
        "digest": digest,
        "alignment_count": len(records),
        "active_alignment_count": len(active_tag_stix_alignments()),
        "alignments": records,
    }


__all__ = (
    "ALIGNMENT_STATES", "TAG_STIX_ALIGNMENT_BY_TAG", "TAG_STIX_ALIGNMENT_SPECS",
    "TAG_STIX_ALIGNMENT_VERSION", "TagStixAlignmentSpec", "active_attack_tag_ids",
    "active_tag_stix_alignments", "tag_stix_alignment_manifest",
)
