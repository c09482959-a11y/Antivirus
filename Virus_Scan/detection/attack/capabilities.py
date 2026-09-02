"""Immutable source-proven local scanner capability declarations.

Capabilities describe only fields and atomic/local terms that current production
producers can publish.  They do not bind those terms to ATT&CK Data Components
or grant technique admission.
"""
from __future__ import annotations

from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from types import MappingProxyType

from Virus_Scan.detection.attack.validation import ordered_text_tuple
from Virus_Scan.detection.registries.tag_taxonomy_registry import tag_class_for

SCANNER_CAPABILITY_VERSION = "stage2636_11020_scanner_capability_v2"
SCANNER_CAPABILITY_STATES = frozenset({"partial", "production_reachable", "unavailable"})
_CAPABILITY_ID = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_ALLOWED_MODALITIES = frozenset({
    "static_string",
    "static_structure",
    "static_control_flow",
    "dynamic_runtime",
    "host_telemetry",
    "network_telemetry",
    "yara_match",
    "metadata",
    "derived",
})
_ALLOWED_FIELDS = frozenset({
    "actor_identity",
    "artifact_identity",
    "connection_identity",
    "directness",
    "host_identity",
    "integrity_status",
    "modality",
    "observation_id",
    "ordinal",
    "platform",
    "process_identity",
    "producer_id",
    "root_observation_id",
    "source_location",
    "stage_id",
    "target_identity",
    "timestamp",
    "timing_provenance",
})


@dataclass(frozen=True, slots=True)
class ScannerCapabilitySpec:
    """One production producer's bounded local observation capability."""

    capability_id: str
    producer_id: str
    source_paths: tuple[str, ...]
    observable_tag_ids: tuple[str, ...]
    supported_modalities: tuple[str, ...]
    supported_platforms: tuple[str, ...]
    emitted_observation_fields: tuple[str, ...]
    capability_state: str
    limitation_reasons: tuple[str, ...]
    version: str = SCANNER_CAPABILITY_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ScannerCapabilitySpec:
            raise TypeError("scanner_capability_owner_invalid")
        capability_id = exact_bounded_text(
            self.capability_id, "scanner_capability_id_invalid", maximum=128,
        )
        if _CAPABILITY_ID.fullmatch(capability_id) is None:
            raise ValueError("scanner_capability_id_invalid")
        producer_id = exact_bounded_text(
            self.producer_id, "scanner_capability_producer_invalid", maximum=128,
        )
        source_paths = ordered_text_tuple(
            self.source_paths, "scanner_capability_source_paths_invalid", maximum_items=16,
        )
        tags = ordered_text_tuple(
            self.observable_tag_ids, "scanner_capability_tags_invalid", maximum_items=128,
        )
        modalities = ordered_text_tuple(
            self.supported_modalities,
            "scanner_capability_modalities_invalid",
            maximum_items=16,
        )
        platforms = ordered_text_tuple(
            self.supported_platforms,
            "scanner_capability_platforms_invalid",
            maximum_items=16,
        )
        fields = ordered_text_tuple(
            self.emitted_observation_fields,
            "scanner_capability_fields_invalid",
            maximum_items=32,
        )
        state = exact_bounded_text(
            self.capability_state, "scanner_capability_state_invalid", maximum=32,
        )
        limitations = ordered_text_tuple(
            self.limitation_reasons,
            "scanner_capability_limitations_invalid",
            maximum_items=32,
        )
        if state not in SCANNER_CAPABILITY_STATES:
            raise ValueError("scanner_capability_state_invalid")
        if any(item not in _ALLOWED_MODALITIES for item in modalities):
            raise ValueError("scanner_capability_modalities_invalid")
        if any(item not in _ALLOWED_FIELDS for item in fields):
            raise ValueError("scanner_capability_fields_invalid")
        if any(not tag_class_for(item) for item in tags):
            raise ValueError("scanner_capability_unknown_tag")
        if state == "unavailable":
            if tags or modalities or platforms or fields or not limitations:
                raise ValueError("scanner_capability_unavailable_contract_invalid")
        elif not source_paths or not tags or not modalities or not fields:
            raise ValueError("scanner_capability_fields_required")
        if state == "production_reachable" and limitations:
            raise ValueError("scanner_capability_reachable_limitation_invalid")
        object.__setattr__(self, "capability_id", capability_id)
        object.__setattr__(self, "producer_id", producer_id)
        object.__setattr__(self, "source_paths", source_paths)
        object.__setattr__(self, "observable_tag_ids", tags)
        object.__setattr__(self, "supported_modalities", modalities)
        object.__setattr__(self, "supported_platforms", platforms)
        object.__setattr__(self, "emitted_observation_fields", fields)
        object.__setattr__(self, "capability_state", state)
        object.__setattr__(self, "limitation_reasons", limitations)
        object.__setattr__(self, "version", exact_bounded_text(
            self.version, "scanner_capability_version_invalid", maximum=128,
        ))

    def to_record(self) -> dict[str, object]:
        return {
            "capability_id": self.capability_id,
            "producer_id": self.producer_id,
            "source_paths": self.source_paths,
            "observable_tag_ids": self.observable_tag_ids,
            "supported_modalities": self.supported_modalities,
            "supported_platforms": self.supported_platforms,
            "emitted_observation_fields": self.emitted_observation_fields,
            "capability_state": self.capability_state,
            "limitation_reasons": self.limitation_reasons,
            "version": self.version,
        }


_ARTIFACT_FIELDS = (
    "artifact_identity",
    "directness",
    "integrity_status",
    "modality",
    "observation_id",
    "producer_id",
    "root_observation_id",
    "source_location",
    "stage_id",
    "timing_provenance",
)

SCANNER_CAPABILITIES = (
    ScannerCapabilitySpec(
        capability_id="scanner.full_analysis_string_scanner",
        producer_id="full_analysis_string_scanner",
        source_paths=(
            "Virus_Scan/detection/enrichment/full_analysis/input_stage.py",
            "Virus_Scan/heuristics/script_exec.py",
            "Virus_Scan/scanners/config/defaults/text_policy.json",
            "Virus_Scan/scanners/strings.py",
            "Virus_Scan/scanners/text_contextual_tags.py",
            "Virus_Scan/scanners/text_validation_gates.py",
        ),
        observable_tag_ids=(
            "admin_share_access",
            "amsi_scanbuffer_patch",
            "cmd_exec",
            "credential_dump_attempt",
            "defender_disable",
            "encoded_powershell",
            "etw_eventwrite_patch",
            "lsass_access",
            "memory_allocate",
            "memory_dump",
            "memory_protect",
            "memory_read",
            "memory_write",
            "network_download",
            "powershell_exec",
            "process_exec",
            "smb_activity",
            "thread_execution",
        ),
        supported_modalities=("static_string",),
        supported_platforms=(),
        emitted_observation_fields=_ARTIFACT_FIELDS,
        capability_state="partial",
        limitation_reasons=(
            "platform_not_emitted",
            "scanner_terms_share_artifact_root",
            "structured_actor_target_process_unavailable",
        ),
    ),
    ScannerCapabilitySpec(
        capability_id="scanner.static_binary_raw",
        producer_id="static_binary_raw",
        source_paths=(
            "Virus_Scan/routing/extension_scan_handlers.py",
            "Virus_Scan/scanners/binary_micro_stage.py",
            "Virus_Scan/scanners/binary_pe_surface.py",
            "Virus_Scan/scanners/config/defaults/binary_policy.json",
            "Virus_Scan/scanners/raw_chunk_collectors.py",
        ),
        observable_tag_ids=(
            "file_write",
            "memory_allocate",
            "memory_protect",
            "memory_write",
            "network_download",
            "process_exec",
            "thread_execution",
        ),
        supported_modalities=("static_structure",),
        supported_platforms=(),
        emitted_observation_fields=_ARTIFACT_FIELDS,
        capability_state="partial",
        limitation_reasons=(
            "platform_not_emitted",
            "scanner_terms_share_artifact_root",
            "structured_actor_target_process_unavailable",
        ),
    ),
    ScannerCapabilitySpec(
        capability_id="scanner.micro_pe_api_raw",
        producer_id="micro_pe_api_raw",
        source_paths=(
            "Virus_Scan/routing/extension_scan_handlers.py",
            "Virus_Scan/scanners/binary_micro_stage.py",
        ),
        observable_tag_ids=(
            "memory_allocate",
            "memory_protect",
            "memory_write",
            "thread_execution",
        ),
        supported_modalities=("static_structure",),
        supported_platforms=(),
        emitted_observation_fields=_ARTIFACT_FIELDS,
        capability_state="partial",
        limitation_reasons=(
            "platform_not_emitted",
            "scanner_terms_share_artifact_root",
            "structured_process_target_unavailable",
        ),
    ),
    ScannerCapabilitySpec(
        capability_id="scanner.python_renpy_static_analysis",
        producer_id="python_renpy_static_analysis",
        source_paths=(
            "Virus_Scan/contracts/static_program_analysis.py",
            "Virus_Scan/routing/extension_scan_router.py",
            "Virus_Scan/scanners/static_program_analysis/python_frontend.py",
        ),
        observable_tag_ids=(
            "static_create_remote_thread_operation",
            "static_encoded_powershell_launch_operation",
            "static_minidump_write_dump_operation",
            "static_open_process_operation",
            "static_virtual_alloc_ex_operation",
            "static_virtual_protect_ex_operation",
            "static_write_process_memory_operation",
        ),
        supported_modalities=("static_control_flow",),
        supported_platforms=("windows",),
        emitted_observation_fields=(
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
        ),
        capability_state="production_reachable",
        limitation_reasons=(),
    ),
    ScannerCapabilitySpec(
        capability_id="scanner.api_call_classifier",
        producer_id="api_call_classifier",
        source_paths=(
            "Virus_Scan/detection/enrichment/full_analysis/api_context.py",
            "Virus_Scan/detection/tags/process/api_tags.py",
        ),
        observable_tag_ids=("memory_read", "thread_execution"),
        supported_modalities=("static_structure",),
        supported_platforms=(),
        emitted_observation_fields=(
            "artifact_identity",
            "directness",
            "integrity_status",
            "modality",
            "observation_id",
            "ordinal",
            "producer_id",
            "root_observation_id",
            "source_location",
            "stage_id",
            "timing_provenance",
        ),
        capability_state="partial",
        limitation_reasons=(
            "api_group_lacks_specific_target_identity",
            "platform_not_emitted",
        ),
    ),
)

if len({item.capability_id for item in SCANNER_CAPABILITIES}) != len(SCANNER_CAPABILITIES):
    raise RuntimeError("scanner_capability_duplicate_id")
if len({item.producer_id for item in SCANNER_CAPABILITIES}) != len(SCANNER_CAPABILITIES):
    raise RuntimeError("scanner_capability_duplicate_producer")

SCANNER_CAPABILITY_BY_ID = MappingProxyType({
    item.capability_id: item for item in SCANNER_CAPABILITIES
})
SCANNER_CAPABILITY_BY_PRODUCER = MappingProxyType({
    item.producer_id: item for item in SCANNER_CAPABILITIES
})


def scanner_capability_manifest() -> dict[str, object]:
    records = tuple(item.to_record() for item in SCANNER_CAPABILITIES)
    digest = sha256(json.dumps(
        records, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()
    return {
        "version": SCANNER_CAPABILITY_VERSION,
        "digest": digest,
        "capability_count": len(records),
        "production_reachable_count": sum(
            item.capability_state == "production_reachable"
            for item in SCANNER_CAPABILITIES
        ),
        "records": records,
    }


__all__ = (
    "SCANNER_CAPABILITIES",
    "SCANNER_CAPABILITY_BY_ID",
    "SCANNER_CAPABILITY_BY_PRODUCER",
    "SCANNER_CAPABILITY_STATES",
    "SCANNER_CAPABILITY_VERSION",
    "ScannerCapabilitySpec",
    "scanner_capability_manifest",
)
