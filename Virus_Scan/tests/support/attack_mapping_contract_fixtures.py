"""Direct ATT&CK mapper contract fixtures; never semantic evaluation data."""
from __future__ import annotations

import hashlib
import json

from Virus_Scan.contracts.artifact_evidence_snapshot import ArtifactEvidenceSnapshot
from Virus_Scan.contracts.artifact_read_snapshot import ArtifactReadLedger, ArtifactReadSnapshot
from Virus_Scan.contracts.chain_evidence import (
    ChainCandidate, ChainDecision, ChainEvent, ChainEvidence, ChainExplanation,
    MatchedChainStep,
)
from Virus_Scan.contracts.detection_observation import (
    DetectionObservation, ObservationSourceLocation, deterministic_observation_id,
)
from Virus_Scan.contracts.yara_hits import unavailable_yara_scan_result
from Virus_Scan.contracts.evidence_discovery_plan import EvidenceDiscoveryBudget
from Virus_Scan.contracts.model_context_snapshot import ModelContextSnapshot
from Virus_Scan.tests.support.model_context_fixtures import model_projection_identity_fixture
from Virus_Scan.detection.attack.candidate_retrieval import unavailable_attack_candidate_retrieval
from Virus_Scan.detection.attack.evidence_discovery import build_evidence_discovery_plan
from Virus_Scan.detection.attack.explainability import build_attack_explainability
from Virus_Scan.detection.attack.integrity import git_blob_sha1_bytes, sha256_bytes
from Virus_Scan.detection.attack.implementations import ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID
from Virus_Scan.detection.attack.mapping.contracts import AttackTechniquePolicy
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICIES
from Virus_Scan.detection.attack.mapping.mapper import map_attack_evidence
from Virus_Scan.detection.attack.evaluation_stage import unavailable_attack_mapping_result
from Virus_Scan.detection.evidence.artifact_session import ArtifactEvidenceSession
from Virus_Scan.runtime.api import mitre_runtime_snapshot
from Virus_Scan.detection.attack.stix_importer import import_stix_bundle
from Virus_Scan.detection.registries.chain_registry import CHAIN_RULE_INDEX

_EMPTY_CHAIN = ChainEvidence("contract_fixture_empty_v1", "empty")


def _stix_id(kind: str, number: int) -> str:
    return f"{kind}--{number:08x}-0000-4000-8000-{number:012x}"


def attack_contract_repository():
    tactic_defs = (
        ("TA0002", "Execution", "execution"),
        ("TA0005", "Defense Evasion", "defense-evasion"),
        ("TA0006", "Credential Access", "credential-access"),
        ("TA0008", "Lateral Movement", "lateral-movement"),
        ("TA0010", "Exfiltration", "exfiltration"),
        ("TA0011", "Command and Control", "command-and-control"),
    )
    technique_defs = (
        ("T1003", "OS Credential Dumping", "credential-access", False),
        ("T1021", "Remote Services", "lateral-movement", False),
        ("T1041", "Exfiltration Over C2 Channel", "exfiltration", False),
        ("T1055", "Process Injection", "defense-evasion", False),
        ("T1059", "Command and Scripting Interpreter", "execution", False),
        ("T1059.001", "PowerShell", "execution", True),
        ("T1105", "Ingress Tool Transfer", "command-and-control", False),
        ("T1562", "Impair Defenses", "defense-evasion", False),
        ("T1562.001", "Disable or Modify Tools", "defense-evasion", True),
    )
    objects: list[dict[str, object]] = []
    for index, (attack_id, name, shortname) in enumerate(tactic_defs, 1):
        objects.append({
            "type": "x-mitre-tactic", "id": _stix_id("x-mitre-tactic", index),
            "name": name, "description": "", "x_mitre_shortname": shortname,
            "external_references": [{"source_name": "mitre-attack", "external_id": attack_id}],
        })
    for index, (attack_id, name, shortname, subtechnique) in enumerate(technique_defs, 101):
        row: dict[str, object] = {
            "type": "attack-pattern", "id": _stix_id("attack-pattern", index),
            "name": name, "description": "", "x_mitre_platforms": ["Windows"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": shortname}],
            "external_references": [{"source_name": "mitre-attack", "external_id": attack_id}],
        }
        if subtechnique:
            row["x_mitre_is_subtechnique"] = True
        objects.append(row)
    payload = json.dumps(
        {"type": "bundle", "id": _stix_id("bundle", 999), "objects": objects},
        sort_keys=True,
    ).encode()
    identity = git_blob_sha1_bytes(payload)
    return import_stix_bundle(
        payload, dataset_version=identity, source_ref="contract-fixture",
        expected_git_blob_sha1=identity, computed_git_blob_sha1=identity,
        local_sha256=sha256_bytes(payload),
    )



def _contract_chain_physical_observations(
    chain_evidence: ChainEvidence,
    *,
    already_materialized_root_ids: frozenset[str],
) -> tuple[DetectionObservation, ...]:
    """Materialize missing roots minted by this module's explicit contract fixture."""
    required = set(chain_evidence.scoreable_root_ids) - set(already_materialized_root_ids)
    if not required:
        return ()
    observations: dict[str, DetectionObservation] = {}
    for decision in chain_evidence.decisions:
        for step in decision.candidate.matched_steps:
            event = step.event
            root = event.root_evidence_id
            if root not in required or root in observations:
                continue
            if event.source != "tag_evidence":
                continue
            expected = deterministic_observation_id(
                producer_id="attack_mapping_contract_fixture",
                stage_id="attack_mapping_contract_fixture",
                modality=event.modality,
                platform=event.platform,
                actor_identity=event.actor_identity,
                target_identity=event.target_identity,
                artifact_identity=event.artifact_identity,
                process_identity=event.process_identity,
                host_identity=event.host_identity,
                connection_identity=event.connection_identity,
                source_location=event.source_location,
                ordinal=event.ordinal,
                timestamp=event.timestamp,
            )
            if expected != root or event.observation_id != root:
                continue
            observations[root] = DetectionObservation(
                observation_id=root,
                root_observation_id=root,
                tag=event.term,
                producer_id="attack_mapping_contract_fixture",
                stage_id="attack_mapping_contract_fixture",
                modality=event.modality,
                platform=event.platform,
                actor_identity=event.actor_identity,
                target_identity=event.target_identity,
                artifact_identity=event.artifact_identity,
                process_identity=event.process_identity,
                host_identity=event.host_identity,
                connection_identity=event.connection_identity,
                source_location=event.source_location,
                ordinal=event.ordinal,
                timestamp=event.timestamp,
                timing_provenance=event.timing_provenance,
                integrity_status=event.integrity_status,
                directness=event.directness,
                confidence=1.0,
                evidence={},
                unavailable_reason=event.unavailable_reason,
            )
    missing = required - set(observations)
    if missing:
        raise ValueError("attack_mapping_contract_chain_physical_roots_missing")
    return tuple(observations[root] for root in sorted(observations))


def attack_mapping_evidence_fixture(
    tags,
    chain_evidence,
    *,
    limitations: tuple[str, ...] = (),
    completeness: str = "complete",
) -> ArtifactEvidenceSnapshot:
    """Build immutable direct-mapper evidence without guessing physical roots."""
    digest = hashlib.sha256(b"").hexdigest()
    read_snapshot = ArtifactReadSnapshot(
        canonical_path="/contract/attack-mapping-fixture.bin",
        size=0,
        mtime_ns=0,
        inode=0,
        device=0,
        extension=".bin",
        prefix_bytes=b"",
        tail_bytes=b"",
        content_sha256=digest,
        read_ledger=ArtifactReadLedger(1, 0, 0, 0, 0, 0),
        state="complete",
    )
    yara_result = unavailable_yara_scan_result(
        "contract_fixture_disabled", status="disabled",
    )
    # The production lifecycle remains the sole owner that re-materializes
    # canonical DetectionObservation roots retained by TagEvidence.  Direct
    # mapper tests reuse that owner rather than reproducing its identity logic.
    tag_root_snapshot = ArtifactEvidenceSession(
        artifact_read_snapshot=read_snapshot,
        static_program_analyses=(),
        yara_scan_result=yara_result,
    ).provisional_evidence(
        tag_evidence=tags,
        chain_evidence=_EMPTY_CHAIN,
    )
    observations = {
        item.root_observation_id: item
        for item in tag_root_snapshot.physical_observations
    }
    for item in _contract_chain_physical_observations(
        chain_evidence,
        already_materialized_root_ids=frozenset(observations),
    ):
        observations.setdefault(item.root_observation_id, item)
    return ArtifactEvidenceSnapshot(
        artifact_read_snapshot=read_snapshot,
        physical_observations=tuple(observations[key] for key in sorted(observations)),
        static_program_analyses=(),
        yara_scan_result=yara_result,
        tag_evidence=tags,
        chain_evidence=chain_evidence,
        parser_analysis_limitations=limitations,
        evidence_completeness=completeness,
    )


def unavailable_attack_mapping_fixture(reason: str = "test_attack_mapping_unavailable"):
    return unavailable_attack_mapping_result(reason)


def attack_explainability_context_fixture(
    evidence: ArtifactEvidenceSnapshot,
    mapping,
    *,
    reason: str = "publication_fixture_no_cluster",
):
    """Build the canonical context-only discovery and explainability projection."""
    candidate = unavailable_attack_candidate_retrieval(reason)
    model_context = ModelContextSnapshot(
        projection_identity=model_projection_identity_fixture(),
        source_artifact_evidence_digest=evidence.semantic_digest,
    )
    plan = build_evidence_discovery_plan(
        evidence,
        model_context,
        candidate,
        frontend_capability_query_kinds=(),
        resource_budget=EvidenceDiscoveryBudget(0, 0),
    )
    explainability = build_attack_explainability(evidence, mapping, candidate, plan)
    return candidate, plan, explainability


def unavailable_attack_publication_fixture(
    tags,
    chain_evidence,
    *,
    reason: str = "publication_fixture_no_cluster",
):
    """Build the real immutable context-only publication inputs for unavailable ATT&CK."""
    evidence = attack_mapping_evidence_fixture(tags, chain_evidence)
    mapping = unavailable_attack_mapping_fixture()
    candidate, plan, explainability = attack_explainability_context_fixture(
        evidence, mapping, reason=reason,
    )
    return mapping, candidate, plan, explainability


def current_attack_mapping_fixture(tags, chain_evidence):
    runtime = mitre_runtime_snapshot()
    if not runtime.enabled:
        return unavailable_attack_mapping_result("mitre_disabled")
    if runtime.repository is None:
        reason = runtime.status.get("unavailable_reason", "mitre_repository_unavailable")
        if type(reason) is not str or not reason or len(reason) > 256:
            reason = "mitre_repository_unavailable"
        return unavailable_attack_mapping_result(reason)
    return map_attack_evidence(runtime.repository, attack_mapping_evidence_fixture(tags, chain_evidence))

def _contract_observation_id(
    partition: str,
    technique_id: str,
    index: int,
    modality: str,
    platform: str,
) -> tuple[str, ObservationSourceLocation]:
    location = ObservationSourceLocation(
        "event", event_id=f"{partition}:{technique_id}:{index}",
    )
    observation_id = deterministic_observation_id(
        producer_id="attack_mapping_contract_fixture",
        stage_id="attack_mapping_contract_fixture",
        modality=modality,
        platform=platform,
        actor_identity="",
        target_identity="",
        artifact_identity="artifact:contract-fixture",
        process_identity="",
        host_identity="",
        connection_identity="",
        source_location=location,
        ordinal=index,
        timestamp=float(index),
    )
    return observation_id, location


def _contract_chain_event(
    partition: str,
    technique_id: str,
    chain_id: str,
    index: int,
    modality: str,
    platform: str,
    status: str,
) -> ChainEvent:
    observation_id, location = _contract_observation_id(
        partition, technique_id, index, modality, platform,
    )
    return ChainEvent(
        evidence_id=f"contract:{partition}:{technique_id}:{index}",
        root_evidence_id=observation_id,
        term=f"{chain_id}-anchor-{index}",
        source="tag_evidence",
        ordinal=index,
        timestamp=float(index),
        correlation_group=_policy_group(technique_id),
        evidence_kind="observed",
        observation_id=observation_id,
        modality=modality,
        platform=platform,
        artifact_identity="artifact:contract-fixture",
        source_location=location,
        timing_provenance="contract_order",
        integrity_status="verified",
        directness="direct" if status == "confirmed" else "derived",
    )


def _policy_group(technique_id: str) -> str:
    for policy in ATTACK_TECHNIQUE_POLICIES:
        if policy.technique_id == technique_id:
            return policy.correlation_group
    raise ValueError("attack_mapping_contract_policy_missing")


def attack_chain_contract_fixture(
    policy: AttackTechniquePolicy,
    partition: str,
    *,
    status: str,
    root_count: int,
) -> ChainEvidence:
    chain_id = next((
        chain_id
        for implementation_id in policy.implementation_ids
        for chain_id in ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID[implementation_id].chain_ids
    ), "")
    if not chain_id:
        return _EMPTY_CHAIN
    rule = CHAIN_RULE_INDEX[chain_id]
    implementation = ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID[policy.implementation_ids[0]]
    modality = implementation.required_modalities[0]
    platform = implementation.platforms[0]
    steps = tuple(
        MatchedChainStep(
            step_index=index,
            alternative="contract-anchor",
            event=_contract_chain_event(
                partition,
                policy.technique_id,
                chain_id,
                index,
                modality,
                platform,
                status,
            ),
        )
        for index in range(root_count)
    )
    candidate = ChainCandidate(
        chain_id=chain_id, rule_version=rule.version, family=rule.family,
        order_class="observed_order" if status == "confirmed" else "partial",
        matched_steps=steps,
        missing_step_indexes=() if status == "confirmed" else (root_count,),
        confidence=1.0 if status == "confirmed" else 0.5,
        support=1.0 if status == "confirmed" else 0.5,
        correlation_group=policy.correlation_group, unmet_requirements=(),
    )
    explanation = ChainExplanation(
        chain_id=chain_id, summary=f"contract-only:{status}",
        evidence_ids=tuple(step.event.evidence_id for step in steps),
        root_evidence_ids=tuple(sorted(candidate.distinct_root_ids)),
    )
    decision = ChainDecision(
        rule=rule, candidate=candidate, status=status,
        scoreable=status in {"confirmed", "candidate"}, score_points=0.0,
        operational_severity=0.0, anchor_floor=0.0, explanation=explanation,
    )
    return ChainEvidence(
        registry_version="contract_fixture_chain_registry_v1",
        registry_digest=hashlib.sha256(
            f"{partition}:{policy.technique_id}:{status}".encode()
        ).hexdigest(),
        decisions=(decision,),
    )


__all__ = (
    "attack_chain_contract_fixture",
    "attack_contract_repository",
    "attack_explainability_context_fixture",
    "attack_mapping_evidence_fixture",
    "current_attack_mapping_fixture",
    "unavailable_attack_mapping_fixture",
    "unavailable_attack_publication_fixture",
)
