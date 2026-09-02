"""Single immutable ATT&CK technique admission-policy registry."""
from __future__ import annotations

from types import MappingProxyType
from hashlib import sha256
import json

from Virus_Scan.detection.attack.implementations import ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID
from Virus_Scan.detection.attack.mapping.contracts import AttackTechniquePolicy
from Virus_Scan.detection.attack.versioning import ATTACK_MAPPING_POLICY_VERSION


def _policy(
    technique_id: str,
    implementation_ids: tuple[str, ...],
    admission_state: str,
    supported_claim_scopes: tuple[str, ...],
    correlation_group: str,
) -> AttackTechniquePolicy:
    return AttackTechniquePolicy(
        technique_id=technique_id,
        implementation_ids=implementation_ids,
        admission_state=admission_state,
        supported_claim_scopes=supported_claim_scopes,
        parent_scoring_policy="most_specific_wins",
        correlation_group=correlation_group,
        requirement_digest_set=(),
        evaluation_manifest_digest="",
        calibration_artifact_id="",
        policy_version=ATTACK_MAPPING_POLICY_VERSION,
    )


ATTACK_TECHNIQUE_POLICIES = (
    _policy(
        "T1003", ("local.t1003.lsass_dump",), "candidate_only",
        ("artifact_implementation",), "credential_access",
    ),
    _policy(
        "T1021", ("local.t1021.admin_smb",), "candidate_only",
        ("artifact_implementation",), "lateral_movement",
    ),
    _policy(
        "T1041", ("unsupported.t1041",), "unsupported_by_sensors", (),
        "exfiltration",
    ),
    _policy(
        "T1055", ("local.t1055.process_injection",), "candidate_only",
        ("artifact_implementation",), "process_injection",
    ),
    _policy(
        "T1059", ("unsupported.t1059",), "unsupported_by_sensors", (),
        "command_script",
    ),
    _policy(
        "T1059.001", ("local.t1059.001.encoded_powershell",), "candidate_only",
        ("artifact_implementation",), "powershell",
    ),
    _policy(
        "T1105", ("local.t1105.download_execute",), "candidate_only",
        ("artifact_implementation",), "tool_transfer",
    ),
    _policy(
        "T1562.001", ("local.t1562.001.security_tool_impairment",),
        "retired", (), "impair_defenses",
    ),
)

if len({policy.technique_id for policy in ATTACK_TECHNIQUE_POLICIES}) != len(
    ATTACK_TECHNIQUE_POLICIES
):
    raise RuntimeError("attack_technique_policy_duplicate_technique")
if any(
    implementation_id not in ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID
    or ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID[implementation_id].technique_id
    != policy.technique_id
    for policy in ATTACK_TECHNIQUE_POLICIES
    for implementation_id in policy.implementation_ids
):
    raise RuntimeError("attack_technique_policy_implementation_invalid")

ATTACK_TECHNIQUE_POLICY_BY_ID = MappingProxyType({
    policy.technique_id: policy for policy in ATTACK_TECHNIQUE_POLICIES
})


def attack_technique_policy_manifest() -> dict[str, object]:
    records = tuple(policy.to_record() for policy in ATTACK_TECHNIQUE_POLICIES)
    digest = sha256(json.dumps(
        records, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()
    return {
        "version": ATTACK_MAPPING_POLICY_VERSION,
        "digest": digest,
        "policy_count": len(records),
        "records": records,
    }


__all__ = (
    "ATTACK_TECHNIQUE_POLICIES",
    "ATTACK_TECHNIQUE_POLICY_BY_ID",
    "attack_technique_policy_manifest",
)
