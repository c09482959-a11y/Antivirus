"""ATT&CK-owned cluster-assisted candidate retrieval with zero decision authority.

The retriever consumes immutable physical Tag/Chain evidence plus a read-only
clustering/model context.  It ranks only already-reviewed local ATT&CK
technique policies.  Its output is context-only: it cannot create observations,
Tags, Chains, mapping decisions, or production probability.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Mapping

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.chain_evidence import ChainDecision, ChainEvidence
from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.detection.api import attack_candidate_retrieval_contracts as candidate_contracts
from Virus_Scan.detection.attack.implementations import (
    ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID,
)
from Virus_Scan.detection.attack.mapping.registry import (
    ATTACK_TECHNIQUE_POLICIES,
    attack_technique_policy_manifest,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.contracts.model_context_snapshot import ModelContextSnapshot
from Virus_Scan.models.clustering.context import context_cluster_quality
from Virus_Scan.models.clustering.microcluster_values import microcluster_value
from Virus_Scan.models.clustering.policy import CLUSTER_MODEL_VERSION, CLUSTER_POLICY
from Virus_Scan.models.clustering.state import cluster_metadata
from Virus_Scan.runtime.api import mitre_runtime_snapshot
from Virus_Scan.utils.probability import safe_clamp

_CANDIDATE_POLICY_STATES = frozenset({"candidate_only", "confirmed_enabled", "production_mature"})
_MAX_CANDIDATES = 16
_MAX_SIGNATURES = 256


def _finite_unit(value: object) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        return 0.0
    number = float(value)
    return safe_clamp(number) if isfinite(number) else 0.0


def _text_tuple(value: object, *, limit: int = _MAX_SIGNATURES) -> tuple[str, ...]:
    if type(value) not in (tuple, list, set, frozenset):
        return ()
    items = tuple(value)
    out: set[str] = set()
    for item in items[:limit]:
        if type(item) is str:
            text = str.__str__(item)
            if text and len(text) <= 512:
                out.add(text)
    return tuple(sorted(out))


def _mapping_signal(value: Mapping[str, object], keys: tuple[str, ...]) -> float:
    if not isinstance(value, Mapping):
        return 0.0
    return max((_finite_unit(value.get(key)) for key in keys), default=0.0)


def _candidate_profiles() -> tuple[dict[str, object], ...]:
    profiles: list[dict[str, object]] = []
    for policy in ATTACK_TECHNIQUE_POLICIES:
        if policy.admission_state not in _CANDIDATE_POLICY_STATES:
            continue
        implementations = tuple(
            ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID[item]
            for item in policy.implementation_ids
        )
        chain_ids = tuple(sorted({
            chain_id for implementation in implementations
            for chain_id in implementation.chain_ids
        }))
        if not chain_ids:
            continue
        profiles.append({
            "technique_id": policy.technique_id,
            "implementation_ids": policy.implementation_ids,
            "required_chain_ids": chain_ids,
            "claim_scopes": policy.supported_claim_scopes,
            "admission_state": policy.admission_state,
            "correlation_group": policy.correlation_group,
        })
    return tuple(profiles)


_CANDIDATE_PROFILES = _candidate_profiles()
_CANDIDATE_PROFILE_DIGEST = canonical_json_sha256({
    "retriever_version": candidate_contracts.ATTACK_CANDIDATE_RETRIEVAL_VERSION,
    "policy_manifest": attack_technique_policy_manifest(),
    "profiles": _CANDIDATE_PROFILES,
})


@dataclass(frozen=True, slots=True)
class AttackClusterContext:
    cluster_id: str
    cluster_model_version: str
    cluster_members: int
    trusted_support: int
    maturity: float
    purity: float
    drift: float
    cluster_quality: float
    tag_signature: tuple[str, ...]
    chain_signature: tuple[str, ...]
    behavior_signature: tuple[str, ...]
    available: bool
    unavailable_reason: str
    semantic_digest: str = ""

    def __post_init__(self) -> None:
        if type(self) is not AttackClusterContext:
            raise TypeError("attack_cluster_context_owner_invalid")
        cluster_id = exact_bounded_text(
            self.cluster_id, "attack_cluster_context_id_invalid",
            maximum=256, allow_blank=not self.available,
        )
        model_version = exact_bounded_text(
            self.cluster_model_version, "attack_cluster_model_version_invalid",
            maximum=128, allow_blank=not self.available,
        )
        reason = exact_bounded_text(
            self.unavailable_reason, "attack_cluster_unavailable_reason_invalid",
            maximum=256, allow_blank=self.available,
        )
        if type(self.cluster_members) is not int or self.cluster_members < 0:
            raise ValueError("attack_cluster_member_count_invalid")
        if type(self.trusted_support) is not int or self.trusted_support < 0:
            raise ValueError("attack_cluster_support_invalid")
        tags = _text_tuple(self.tag_signature)
        chains = _text_tuple(self.chain_signature)
        behaviors = _text_tuple(self.behavior_signature)
        if self.available and (not cluster_id or reason):
            raise ValueError("attack_cluster_availability_contract_invalid")
        if not self.available and not reason:
            raise ValueError("attack_cluster_unavailable_reason_required")
        payload = {
            "schema_version": candidate_contracts.ATTACK_CANDIDATE_RETRIEVAL_SCHEMA_VERSION,
            "cluster_id": cluster_id,
            "cluster_model_version": model_version,
            "cluster_members": self.cluster_members,
            "trusted_support": self.trusted_support,
            "maturity": _finite_unit(self.maturity),
            "purity": _finite_unit(self.purity),
            "drift": _finite_unit(self.drift),
            "cluster_quality": _finite_unit(self.cluster_quality),
            "tag_signature": tags,
            "chain_signature": chains,
            "behavior_signature": behaviors,
            "available": self.available is True,
            "unavailable_reason": reason,
        }
        digest = canonical_json_sha256(payload)
        if self.semantic_digest not in ("", digest):
            raise ValueError("attack_cluster_context_digest_mismatch")
        object.__setattr__(self, "cluster_id", cluster_id)
        object.__setattr__(self, "cluster_model_version", model_version)
        object.__setattr__(self, "maturity", payload["maturity"])
        object.__setattr__(self, "purity", payload["purity"])
        object.__setattr__(self, "drift", payload["drift"])
        object.__setattr__(self, "cluster_quality", payload["cluster_quality"])
        object.__setattr__(self, "tag_signature", tags)
        object.__setattr__(self, "chain_signature", chains)
        object.__setattr__(self, "behavior_signature", behaviors)
        object.__setattr__(self, "available", self.available is True)
        object.__setattr__(self, "unavailable_reason", reason)
        object.__setattr__(self, "semantic_digest", digest)

    def to_record(self) -> dict[str, object]:
        return {
            "cluster_id": self.cluster_id,
            "cluster_model_version": self.cluster_model_version,
            "cluster_members": self.cluster_members,
            "trusted_support": self.trusted_support,
            "maturity": self.maturity,
            "purity": self.purity,
            "drift": self.drift,
            "cluster_quality": self.cluster_quality,
            "tag_signature": self.tag_signature,
            "chain_signature": self.chain_signature,
            "behavior_signature": self.behavior_signature,
            "available": self.available,
            "unavailable_reason": self.unavailable_reason,
            "semantic_digest": self.semantic_digest,
        }


@dataclass(frozen=True, slots=True)
class AttackCandidateRank:
    rank: int
    technique_id: str
    implementation_ids: tuple[str, ...]
    claim_scopes: tuple[str, ...]
    admission_state: str
    correlation_group: str
    score: float
    matched_cluster_chain_ids: tuple[str, ...]
    matched_direct_chain_ids: tuple[str, ...]
    shared_physical_root_ids: tuple[str, ...]
    missing_direct_requirements: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.rank) is not int or self.rank < 1 or self.rank > _MAX_CANDIDATES:
            raise ValueError("attack_candidate_rank_invalid")
        technique = exact_bounded_text(
            self.technique_id, "attack_candidate_technique_invalid", maximum=16,
        )
        if not technique.startswith("T"):
            raise ValueError("attack_candidate_technique_invalid")
        object.__setattr__(self, "technique_id", technique)
        object.__setattr__(self, "implementation_ids", _text_tuple(self.implementation_ids, limit=16))
        object.__setattr__(self, "claim_scopes", _text_tuple(self.claim_scopes, limit=16))
        object.__setattr__(self, "admission_state", exact_bounded_text(
            self.admission_state, "attack_candidate_admission_invalid", maximum=32,
        ))
        object.__setattr__(self, "correlation_group", exact_bounded_text(
            self.correlation_group, "attack_candidate_group_invalid", maximum=128,
        ))
        object.__setattr__(self, "score", _finite_unit(self.score))
        object.__setattr__(self, "matched_cluster_chain_ids", _text_tuple(self.matched_cluster_chain_ids, limit=32))
        object.__setattr__(self, "matched_direct_chain_ids", _text_tuple(self.matched_direct_chain_ids, limit=32))
        object.__setattr__(self, "shared_physical_root_ids", _text_tuple(self.shared_physical_root_ids, limit=128))
        object.__setattr__(self, "missing_direct_requirements", _text_tuple(self.missing_direct_requirements, limit=64))

    def to_record(self) -> dict[str, object]:
        return {
            "rank": self.rank,
            "technique_id": self.technique_id,
            "implementation_ids": self.implementation_ids,
            "claim_scopes": self.claim_scopes,
            "admission_state": self.admission_state,
            "correlation_group": self.correlation_group,
            "score": self.score,
            "matched_cluster_chain_ids": self.matched_cluster_chain_ids,
            "matched_direct_chain_ids": self.matched_direct_chain_ids,
            "shared_physical_root_ids": self.shared_physical_root_ids,
            "missing_direct_requirements": self.missing_direct_requirements,
            "evidence_authority": "context_only",
            "eligible_for_confirmation": False,
            "eligible_for_probability": False,
        }


@dataclass(frozen=True, slots=True)
class AttackCandidateRetrievalResult:
    repository_digest: str
    dataset_version: str
    cluster_context: AttackClusterContext
    tag_signatures: tuple[str, ...]
    chain_signatures: tuple[str, ...]
    static_operation_signatures: tuple[str, ...]
    markov_context_signal: float
    temporal_context_signal: float
    candidates: tuple[AttackCandidateRank, ...]
    abstained: bool
    unavailable_reason: str
    semantic_digest: str = ""

    def __post_init__(self) -> None:
        if type(self.cluster_context) is not AttackClusterContext:
            raise TypeError("attack_candidate_cluster_context_required")
        candidates = tuple(item for item in self.candidates if type(item) is AttackCandidateRank)
        if len(candidates) != len(self.candidates) or len(candidates) > _MAX_CANDIDATES:
            raise TypeError("attack_candidate_sequence_invalid")
        if tuple(item.rank for item in candidates) != tuple(range(1, len(candidates) + 1)):
            raise ValueError("attack_candidate_rank_sequence_invalid")
        reason = exact_bounded_text(
            self.unavailable_reason, "attack_candidate_unavailable_reason_invalid",
            maximum=256, allow_blank=not self.abstained,
        )
        if self.abstained is True and (candidates or not reason):
            raise ValueError("attack_candidate_abstention_contract_invalid")
        if self.abstained is not True and (not candidates or reason):
            raise ValueError("attack_candidate_available_contract_invalid")
        payload = {
            "schema_version": candidate_contracts.ATTACK_CANDIDATE_RETRIEVAL_SCHEMA_VERSION,
            "retriever_version": candidate_contracts.ATTACK_CANDIDATE_RETRIEVAL_VERSION,
            "profile_digest": _CANDIDATE_PROFILE_DIGEST,
            "repository_digest": self.repository_digest,
            "dataset_version": self.dataset_version,
            "cluster_context": self.cluster_context.to_record(),
            "tag_signatures": _text_tuple(self.tag_signatures),
            "chain_signatures": _text_tuple(self.chain_signatures),
            "static_operation_signatures": _text_tuple(self.static_operation_signatures),
            "markov_context_signal": _finite_unit(self.markov_context_signal),
            "temporal_context_signal": _finite_unit(self.temporal_context_signal),
            "ranked_candidates": tuple(item.to_record() for item in candidates),
            "candidate_count": len(candidates),
            "abstained": self.abstained is True,
            "unavailable_reason": reason,
            "evidence_authority": "context_only",
            "eligible_for_confirmation": False,
            "eligible_for_probability": False,
            "official_decision_effect": "none",
        }
        digest = canonical_json_sha256(payload)
        if self.semantic_digest not in ("", digest):
            raise ValueError("attack_candidate_retrieval_digest_mismatch")
        object.__setattr__(self, "tag_signatures", payload["tag_signatures"])
        object.__setattr__(self, "chain_signatures", payload["chain_signatures"])
        object.__setattr__(self, "static_operation_signatures", payload["static_operation_signatures"])
        object.__setattr__(self, "markov_context_signal", payload["markov_context_signal"])
        object.__setattr__(self, "temporal_context_signal", payload["temporal_context_signal"])
        object.__setattr__(self, "candidates", candidates)
        object.__setattr__(self, "abstained", self.abstained is True)
        object.__setattr__(self, "unavailable_reason", reason)
        object.__setattr__(self, "semantic_digest", digest)

    def to_record(self) -> dict[str, object]:
        record = {
            "schema_version": candidate_contracts.ATTACK_CANDIDATE_RETRIEVAL_SCHEMA_VERSION,
            "retriever_version": candidate_contracts.ATTACK_CANDIDATE_RETRIEVAL_VERSION,
            "profile_digest": _CANDIDATE_PROFILE_DIGEST,
            "repository_digest": self.repository_digest,
            "dataset_version": self.dataset_version,
            "cluster_context": self.cluster_context.to_record(),
            "tag_signatures": self.tag_signatures,
            "chain_signatures": self.chain_signatures,
            "static_operation_signatures": self.static_operation_signatures,
            "markov_context_signal": self.markov_context_signal,
            "temporal_context_signal": self.temporal_context_signal,
            "ranked_candidates": tuple(item.to_record() for item in self.candidates),
            "candidate_count": len(self.candidates),
            "abstained": self.abstained,
            "unavailable_reason": self.unavailable_reason,
            "evidence_authority": "context_only",
            "eligible_for_confirmation": False,
            "eligible_for_probability": False,
            "official_decision_effect": "none",
            "semantic_digest": self.semantic_digest,
        }
        return record


def unavailable_attack_candidate_retrieval(reason: str) -> AttackCandidateRetrievalResult:
    context = AttackClusterContext(
        cluster_id="", cluster_model_version="", cluster_members=0,
        trusted_support=0, maturity=0.0, purity=0.0, drift=0.0,
        cluster_quality=0.0, tag_signature=(), chain_signature=(),
        behavior_signature=(), available=False, unavailable_reason=reason,
    )
    return AttackCandidateRetrievalResult(
        repository_digest="", dataset_version="", cluster_context=context,
        tag_signatures=(), chain_signatures=(), static_operation_signatures=(),
        markov_context_signal=0.0, temporal_context_signal=0.0,
        candidates=(), abstained=True, unavailable_reason=reason,
    )


def build_attack_cluster_context(node: object, tag_evidence: TagEvidence) -> AttackClusterContext:
    if type(tag_evidence) is not TagEvidence:
        raise TypeError("attack_candidate_tag_evidence_required")
    quality = context_cluster_quality(node, tag_evidence, {})
    if type(quality) is not dict or quality.get("eligible") is not True:
        reason = quality.get("unavailable_reason") if type(quality) is dict else None
        if type(reason) is not str or not reason:
            reason = quality.get("reason") if type(quality) is dict else None
        if type(reason) is not str or not reason:
            reason = "cluster_context_unavailable"
        return AttackClusterContext(
            cluster_id="", cluster_model_version="", cluster_members=0,
            trusted_support=0, maturity=0.0, purity=0.0, drift=0.0,
            cluster_quality=0.0, tag_signature=(), chain_signature=(),
            behavior_signature=(), available=False, unavailable_reason=reason,
        )
    cluster_id = quality.get("cluster_id")
    if type(cluster_id) is not str or not cluster_id:
        return AttackClusterContext(
            cluster_id="", cluster_model_version="", cluster_members=0,
            trusted_support=0, maturity=0.0, purity=0.0, drift=0.0,
            cluster_quality=0.0, tag_signature=(), chain_signature=(),
            behavior_signature=(), available=False, unavailable_reason="cluster_identity_unavailable",
        )
    snapshot = cluster_metadata().get(cluster_id, {})
    trusted = microcluster_value(snapshot, "trusted_sample_count", 0)
    trusted = trusted if type(trusted) is int and trusted >= 0 else 0
    malicious_ratio = _finite_unit(microcluster_value(snapshot, "malicious_ratio", 0.0))
    benign_ratio = _finite_unit(microcluster_value(snapshot, "benign_ratio", 0.0))
    drift_alarm = microcluster_value(snapshot, "drift_alarm", False) is True
    purity_alarm = microcluster_value(snapshot, "purity_limit_exceeded", False) is True
    return AttackClusterContext(
        cluster_id=cluster_id,
        cluster_model_version=CLUSTER_MODEL_VERSION,
        cluster_members=quality.get("cluster_members", 0),
        trusted_support=trusted,
        maturity=min(1.0, trusted / float(max(1, CLUSTER_POLICY.minimum_trusted_support))),
        purity=max(malicious_ratio, benign_ratio),
        drift=1.0 if drift_alarm or purity_alarm else 0.0,
        cluster_quality=quality.get("cluster_quality", 0.0),
        tag_signature=_text_tuple(microcluster_value(snapshot, "tag_signature", ())),
        chain_signature=_text_tuple(microcluster_value(snapshot, "chain_signature", ())),
        behavior_signature=_text_tuple(microcluster_value(snapshot, "behavior_signature", ())),
        available=True,
        unavailable_reason="",
    )


def _chain_signature_matches(signature: str, chain_id: str) -> bool:
    return (
        type(signature) is str
        and (signature.startswith("confirmed:") or signature.startswith("candidate:"))
        and (":" + chain_id + ":") in signature
    )


def _direct_chain_index(chain_evidence: ChainEvidence) -> dict[str, tuple[ChainDecision, ...]]:
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("attack_candidate_chain_evidence_required")
    index: dict[str, list[ChainDecision]] = {}
    for decision in chain_evidence.decisions:
        if decision.status not in {"confirmed", "candidate"}:
            continue
        index.setdefault(decision.candidate.chain_id, []).append(decision)
    return {key: tuple(value) for key, value in index.items()}


def rank_attack_candidates(
    tag_evidence: TagEvidence,
    chain_evidence: ChainEvidence,
    model_context: ModelContextSnapshot,
    cluster_context: AttackClusterContext,
    *,
    repository_digest: str,
    dataset_version: str,
) -> AttackCandidateRetrievalResult:
    if type(tag_evidence) is not TagEvidence:
        raise TypeError("attack_candidate_tag_evidence_required")
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("attack_candidate_chain_evidence_required")
    if type(model_context) is not ModelContextSnapshot:
        raise TypeError("attack_candidate_model_context_required")
    if type(cluster_context) is not AttackClusterContext:
        raise TypeError("attack_candidate_cluster_context_required")
    tag_signatures = tuple(sorted({
        record.canonical_tag_id for record in tag_evidence.records
        if record.evidence_kind != "failure" and record.polarity == "positive"
    }))
    static_operations = tuple(sorted({
        record.canonical_tag_id for record in tag_evidence.records
        if record.modality == "static_control_flow"
        and record.canonical_tag_id.startswith("static_")
        and record.canonical_tag_id.endswith("_operation")
        and record.evidence_kind != "failure"
    }))
    chain_signatures = tuple(sorted({
        ":".join((
            decision.status, decision.candidate.family,
            decision.candidate.chain_id, decision.candidate.rule_version,
        ))
        for decision in chain_evidence.decisions
        if decision.status in {"confirmed", "candidate"}
    }))
    markov_signal = _mapping_signal(
        model_context.markov_features, ("transition", "rarity", "pair_anomaly", "anomaly"),
    )
    temporal_signal = _mapping_signal(
        model_context.temporal_features, ("belief", "anomaly", "confidence"),
    )
    if not cluster_context.available:
        return AttackCandidateRetrievalResult(
            repository_digest=repository_digest, dataset_version=dataset_version,
            cluster_context=cluster_context, tag_signatures=tag_signatures,
            chain_signatures=chain_signatures,
            static_operation_signatures=static_operations,
            markov_context_signal=markov_signal,
            temporal_context_signal=temporal_signal,
            candidates=(), abstained=True,
            unavailable_reason=cluster_context.unavailable_reason,
        )
    cluster_tags = set(cluster_context.tag_signature)
    operation_overlap = (
        len(set(static_operations) & cluster_tags)
        / max(1, len(set(static_operations) | cluster_tags))
    ) if static_operations or cluster_tags else 0.0
    direct_index = _direct_chain_index(chain_evidence)
    raw: list[tuple[float, str, dict[str, object]]] = []
    for profile in _CANDIDATE_PROFILES:
        required = tuple(profile["required_chain_ids"])
        cluster_matches = tuple(
            chain_id for chain_id in required
            if any(_chain_signature_matches(signature, chain_id) for signature in cluster_context.chain_signature)
        )
        if not cluster_matches:
            continue
        direct_matches = tuple(chain_id for chain_id in required if chain_id in direct_index)
        roots = tuple(sorted({
            root
            for chain_id in direct_matches
            for decision in direct_index[chain_id]
            for root in decision.candidate.distinct_root_ids
        }))
        missing = tuple(
            "chain:" + chain_id for chain_id in required if chain_id not in direct_index
        )
        if not roots:
            missing = (*missing, "physical_root_evidence")
        cluster_coverage = len(cluster_matches) / max(1, len(required))
        direct_coverage = len(direct_matches) / max(1, len(required))
        score = safe_clamp(
            0.55 * cluster_coverage
            + 0.20 * direct_coverage
            + 0.15 * cluster_context.cluster_quality
            + 0.05 * operation_overlap
            + 0.025 * markov_signal
            + 0.025 * temporal_signal
        )
        raw.append((score, str(profile["technique_id"]), {
            **profile,
            "score": score,
            "cluster_matches": cluster_matches,
            "direct_matches": direct_matches,
            "roots": roots,
            "missing": missing,
        }))
    raw.sort(key=lambda item: (-item[0], item[1]))
    candidates = tuple(
        AttackCandidateRank(
            rank=index,
            technique_id=str(item[2]["technique_id"]),
            implementation_ids=tuple(item[2]["implementation_ids"]),
            claim_scopes=tuple(item[2]["claim_scopes"]),
            admission_state=str(item[2]["admission_state"]),
            correlation_group=str(item[2]["correlation_group"]),
            score=item[0],
            matched_cluster_chain_ids=tuple(item[2]["cluster_matches"]),
            matched_direct_chain_ids=tuple(item[2]["direct_matches"]),
            shared_physical_root_ids=tuple(item[2]["roots"]),
            missing_direct_requirements=tuple(item[2]["missing"]),
        )
        for index, item in enumerate(raw[:_MAX_CANDIDATES], 1)
    )
    return AttackCandidateRetrievalResult(
        repository_digest=repository_digest, dataset_version=dataset_version,
        cluster_context=cluster_context, tag_signatures=tag_signatures,
        chain_signatures=chain_signatures,
        static_operation_signatures=static_operations,
        markov_context_signal=markov_signal,
        temporal_context_signal=temporal_signal,
        candidates=candidates, abstained=not candidates,
        unavailable_reason="" if candidates else "cluster_no_reviewed_candidate_overlap",
    )


def retrieve_current_attack_candidates(
    node: object,
    tag_evidence: TagEvidence,
    chain_evidence: ChainEvidence,
    model_context: ModelContextSnapshot,
) -> AttackCandidateRetrievalResult:
    if type(tag_evidence) is not TagEvidence:
        raise TypeError("attack_candidate_tag_evidence_required")
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("attack_candidate_chain_evidence_required")
    if type(model_context) is not ModelContextSnapshot:
        raise TypeError("attack_candidate_model_context_required")
    runtime = mitre_runtime_snapshot()
    if not runtime.enabled:
        return unavailable_attack_candidate_retrieval("mitre_disabled")
    if runtime.repository is None:
        return unavailable_attack_candidate_retrieval("mitre_repository_unavailable")
    cluster_context = build_attack_cluster_context(node, tag_evidence)
    return rank_attack_candidates(
        tag_evidence, chain_evidence, model_context, cluster_context,
        repository_digest=runtime.repository.digest,
        dataset_version=runtime.repository.version.dataset_version,
    )


__all__ = (
    "AttackCandidateRank",
    "AttackCandidateRetrievalResult",
    "AttackClusterContext",
    "build_attack_cluster_context",
    "rank_attack_candidates",
    "retrieve_current_attack_candidates",
    "unavailable_attack_candidate_retrieval",
)
