"""Immutable reviewed bindings from ATT&CK techniques to canonical Chain rules."""
from __future__ import annotations

from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from types import MappingProxyType

from Virus_Scan.detection.attack.validation import exact_hex, official_attack_id, ordered_text_tuple
from Virus_Scan.detection.registries.chain_registry import CHAIN_RULE_INDEX

ATTACK_ANALYTIC_IMPLEMENTATION_VERSION = "stage2636_11020_attack_implementation_v2"
ATTACK_ANALYTIC_SUPPORT_MODES = frozenset({
    "exact_official", "local_artifact", "partial", "unsupported",
})
ATTACK_ANALYTIC_CLAIM_SCOPES = frozenset({
    "artifact_implementation", "runtime_behavior", "host_telemetry",
    "network_telemetry", "unavailable",
})
ATTACK_ANALYTIC_ADMISSION_STATES = frozenset({
    "unsupported", "candidate_only", "confirmed_enabled", "quarantined",
})
_IMPLEMENTATION_ID = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_ALLOWED_MODALITIES = frozenset({
    "static_string", "static_structure", "static_control_flow", "dynamic_runtime",
    "host_telemetry", "network_telemetry", "yara_match", "metadata", "derived",
})


@dataclass(frozen=True, slots=True)
class AttackAnalyticImplementationSpec:
    """One local implementation of an official or explicitly local Analytic."""

    implementation_id: str
    technique_id: str
    strategy_id: str
    analytic_id: str
    chain_ids: tuple[str, ...]
    required_data_component_ids: tuple[str, ...]
    support_mode: str
    claim_scope: str
    platforms: tuple[str, ...]
    required_modalities: tuple[str, ...]
    requirement_digest: str
    evaluation_manifest_digest: str
    admission_state: str
    version: str = ATTACK_ANALYTIC_IMPLEMENTATION_VERSION

    def __post_init__(self) -> None:
        if type(self) is not AttackAnalyticImplementationSpec:
            raise TypeError("attack_implementation_owner_invalid")
        implementation_id = exact_bounded_text(
            self.implementation_id, "attack_implementation_id_invalid", maximum=128,
        )
        if _IMPLEMENTATION_ID.fullmatch(implementation_id) is None:
            raise ValueError("attack_implementation_id_invalid")
        technique_id = official_attack_id(
            self.technique_id, "attack_implementation_technique_invalid",
        )
        if not technique_id.startswith("T") or technique_id.startswith("TA"):
            raise ValueError("attack_implementation_technique_invalid")
        strategy_id = exact_bounded_text(
            self.strategy_id, "attack_implementation_strategy_invalid",
            maximum=16, allow_blank=True,
        )
        analytic_id = exact_bounded_text(
            self.analytic_id, "attack_implementation_analytic_invalid",
            maximum=16, allow_blank=True,
        )
        if strategy_id and not official_attack_id(
            strategy_id, "attack_implementation_strategy_invalid",
        ).startswith("DET"):
            raise ValueError("attack_implementation_strategy_invalid")
        if analytic_id and not official_attack_id(
            analytic_id, "attack_implementation_analytic_invalid",
        ).startswith("AN"):
            raise ValueError("attack_implementation_analytic_invalid")
        chain_ids = ordered_text_tuple(
            self.chain_ids, "attack_implementation_chains_invalid", maximum_items=16,
        )
        data_components = ordered_text_tuple(
            self.required_data_component_ids,
            "attack_implementation_data_components_invalid",
            maximum_items=32,
        )
        if any(not official_attack_id(
            item, "attack_implementation_data_component_invalid",
        ).startswith("DC") for item in data_components):
            raise ValueError("attack_implementation_data_component_invalid")
        support_mode = exact_bounded_text(
            self.support_mode, "attack_implementation_support_mode_invalid", maximum=32,
        )
        claim_scope = exact_bounded_text(
            self.claim_scope, "attack_implementation_claim_scope_invalid", maximum=32,
        )
        admission_state = exact_bounded_text(
            self.admission_state, "attack_implementation_admission_invalid", maximum=32,
        )
        if support_mode not in ATTACK_ANALYTIC_SUPPORT_MODES:
            raise ValueError("attack_implementation_support_mode_invalid")
        if claim_scope not in ATTACK_ANALYTIC_CLAIM_SCOPES:
            raise ValueError("attack_implementation_claim_scope_invalid")
        if admission_state not in ATTACK_ANALYTIC_ADMISSION_STATES:
            raise ValueError("attack_implementation_admission_invalid")
        platforms = ordered_text_tuple(
            self.platforms, "attack_implementation_platforms_invalid", maximum_items=32,
        )
        modalities = ordered_text_tuple(
            self.required_modalities,
            "attack_implementation_modalities_invalid",
            maximum_items=16,
        )
        if any(item not in _ALLOWED_MODALITIES for item in modalities):
            raise ValueError("attack_implementation_modalities_invalid")
        requirement_digest = self.requirement_digest
        evaluation_digest = self.evaluation_manifest_digest
        if support_mode == "exact_official":
            if not strategy_id or not analytic_id or not data_components:
                raise ValueError("attack_implementation_official_fields_required")
            requirement_digest = exact_hex(
                requirement_digest, "attack_implementation_requirement_digest_invalid",
                length=64,
            )
        elif strategy_id or analytic_id or data_components or requirement_digest:
            raise ValueError("attack_implementation_local_official_claim_invalid")
        if support_mode == "unsupported":
            if chain_ids or claim_scope != "unavailable" or admission_state != "unsupported":
                raise ValueError("attack_implementation_unsupported_contract_invalid")
        elif not chain_ids or not platforms or not modalities or claim_scope == "unavailable":
            raise ValueError("attack_implementation_local_fields_required")
        if admission_state == "confirmed_enabled":
            evaluation_digest = exact_hex(
                evaluation_digest, "attack_implementation_evaluation_digest_invalid",
                length=64,
            )
        elif type(evaluation_digest) is not str or evaluation_digest:
            raise ValueError("attack_implementation_inactive_evaluation_digest_invalid")
        if any(chain_id not in CHAIN_RULE_INDEX for chain_id in chain_ids):
            raise ValueError("attack_implementation_chain_missing")
        object.__setattr__(self, "implementation_id", implementation_id)
        object.__setattr__(self, "technique_id", technique_id)
        object.__setattr__(self, "strategy_id", strategy_id)
        object.__setattr__(self, "analytic_id", analytic_id)
        object.__setattr__(self, "chain_ids", chain_ids)
        object.__setattr__(self, "required_data_component_ids", data_components)
        object.__setattr__(self, "support_mode", support_mode)
        object.__setattr__(self, "claim_scope", claim_scope)
        object.__setattr__(self, "platforms", platforms)
        object.__setattr__(self, "required_modalities", modalities)
        object.__setattr__(self, "requirement_digest", requirement_digest)
        object.__setattr__(self, "evaluation_manifest_digest", evaluation_digest)
        object.__setattr__(self, "admission_state", admission_state)
        object.__setattr__(self, "version", exact_bounded_text(
            self.version, "attack_implementation_version_invalid", maximum=128,
        ))

    def to_record(self) -> dict[str, object]:
        return {
            "implementation_id": self.implementation_id,
            "technique_id": self.technique_id,
            "strategy_id": self.strategy_id,
            "analytic_id": self.analytic_id,
            "chain_ids": self.chain_ids,
            "required_data_component_ids": self.required_data_component_ids,
            "support_mode": self.support_mode,
            "claim_scope": self.claim_scope,
            "platforms": self.platforms,
            "required_modalities": self.required_modalities,
            "requirement_digest": self.requirement_digest,
            "evaluation_manifest_digest": self.evaluation_manifest_digest,
            "admission_state": self.admission_state,
            "version": self.version,
        }


_WINDOWS_LOCAL_MODALITIES = (
    "dynamic_runtime", "host_telemetry", "static_control_flow",
)
_WINDOWS_ARTIFACT_MODALITIES = (
    "dynamic_runtime", "host_telemetry", "static_control_flow", "static_structure",
)

ATTACK_ANALYTIC_IMPLEMENTATIONS = (
    AttackAnalyticImplementationSpec(
        "local.t1003.lsass_dump", "T1003", "", "",
        ("anchor:api_lsass_minidump", "execution.lsass_process_access_to_dump"),
        (), "local_artifact", "artifact_implementation", ("windows",),
        _WINDOWS_LOCAL_MODALITIES, "", "", "candidate_only",
    ),
    AttackAnalyticImplementationSpec(
        "local.t1021.admin_smb", "T1021", "", "",
        ("anchor:lateral_admin_smb",), (), "local_artifact",
        "artifact_implementation", ("windows",),
        ("dynamic_runtime", "host_telemetry", "network_telemetry", "static_control_flow"),
        "", "", "candidate_only",
    ),
    AttackAnalyticImplementationSpec(
        "unsupported.t1041", "T1041", "", "", (), (), "unsupported",
        "unavailable", (), (), "", "", "unsupported",
    ),
    AttackAnalyticImplementationSpec(
        "local.t1055.process_injection", "T1055", "", "",
        ("static.artifact.virtualallocex_writeprocessmemory_createremotethread",),
        (), "local_artifact", "artifact_implementation", ("windows",),
        _WINDOWS_LOCAL_MODALITIES, "", "", "candidate_only",
    ),
    AttackAnalyticImplementationSpec(
        "unsupported.t1059", "T1059", "", "", (), (), "unsupported",
        "unavailable", (), (), "", "", "unsupported",
    ),
    AttackAnalyticImplementationSpec(
        "local.t1059.001.encoded_powershell", "T1059.001", "", "",
        ("static.artifact.encoded_powershell_launch",), (), "local_artifact",
        "artifact_implementation", ("windows",), _WINDOWS_ARTIFACT_MODALITIES,
        "", "", "candidate_only",
    ),
    AttackAnalyticImplementationSpec(
        "local.t1105.download_execute", "T1105", "", "",
        ("execution.download_file_execute",), (), "partial",
        "artifact_implementation", ("linux", "macos", "windows"),
        ("dynamic_runtime", "host_telemetry", "network_telemetry", "static_control_flow"),
        "", "", "candidate_only",
    ),
    AttackAnalyticImplementationSpec(
        "local.t1562.001.security_tool_impairment", "T1562.001", "", "",
        (
            "anchor:amsi_patch_execution",
            "anchor:etw_patch_execution",
            "defender_tamper_execution_chain",
        ),
        (), "local_artifact", "artifact_implementation", ("windows",),
        _WINDOWS_ARTIFACT_MODALITIES, "", "", "quarantined",
    ),
)

if len({item.implementation_id for item in ATTACK_ANALYTIC_IMPLEMENTATIONS}) != len(
    ATTACK_ANALYTIC_IMPLEMENTATIONS
):
    raise RuntimeError("attack_implementation_duplicate_id")
ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID = MappingProxyType({
    item.implementation_id: item for item in ATTACK_ANALYTIC_IMPLEMENTATIONS
})
ATTACK_ANALYTIC_IMPLEMENTATIONS_BY_TECHNIQUE = MappingProxyType({
    technique_id: tuple(
        item for item in ATTACK_ANALYTIC_IMPLEMENTATIONS if item.technique_id == technique_id
    )
    for technique_id in sorted({item.technique_id for item in ATTACK_ANALYTIC_IMPLEMENTATIONS})
})


def attack_analytic_implementation_manifest() -> dict[str, object]:
    records = tuple(item.to_record() for item in ATTACK_ANALYTIC_IMPLEMENTATIONS)
    digest = sha256(json.dumps(
        records, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()
    return {
        "version": ATTACK_ANALYTIC_IMPLEMENTATION_VERSION,
        "digest": digest,
        "implementation_count": len(records),
        "confirmed_enabled_count": sum(
            item.admission_state == "confirmed_enabled"
            for item in ATTACK_ANALYTIC_IMPLEMENTATIONS
        ),
        "records": records,
    }


__all__ = (
    "ATTACK_ANALYTIC_ADMISSION_STATES", "ATTACK_ANALYTIC_CLAIM_SCOPES",
    "ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID", "ATTACK_ANALYTIC_IMPLEMENTATION_VERSION",
    "ATTACK_ANALYTIC_IMPLEMENTATIONS", "ATTACK_ANALYTIC_IMPLEMENTATIONS_BY_TECHNIQUE",
    "ATTACK_ANALYTIC_SUPPORT_MODES", "AttackAnalyticImplementationSpec",
    "attack_analytic_implementation_manifest",
)
