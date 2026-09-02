from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from Virus_Scan.contracts.tag_evidence import distinct_positive_root_ids_for_tags
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.utils.probability import safe_clamp


def intrinsic_probability_scores(
    tags: object,
    *,
    tag_entropy_fn,
) -> dict[str, float]:
    """Return intrinsic probabilities without uncalibrated YARA authority."""
    if type(tags) is not TagEvidence:
        raise TypeError("intrinsic_probability_scores_requires_tag_evidence")
    kinds = frozenset({"observed", "normalized", "derived", "composite"})
    root_count = len(distinct_positive_root_ids_for_tags(
        tags.records, tags.tags, allowed_evidence_kinds=kinds,
    ))
    exec_roots = distinct_positive_root_ids_for_tags(
        tags.records, ("process_exec", "cmd_exec", "powershell_exec"),
        allowed_evidence_kinds=kinds,
    )
    return {
        "p_yara": 0.0,
        "p_entropy": min(1.0, tag_entropy_fn(tags.tags) / 5.0),
        "p_behavior": min(1.0, root_count / 20.0),
        "p_exec": 1.0 if exec_roots else 0.0,
    }


def zero_unavailable_scores(
    scores: MutableMapping[str, float],
    reasons: Mapping[str, str | None],
) -> None:
    for name in (
        "p_attack_intelligence",
        "p_bucket",
        "p_cluster",
        "p_engine",
        "p_graph",
        "p_graph_chain",
        "p_markov",
        "p_profile",
        "p_temporal",
        "p_vector",
        "p_yara",
    ):
        reason_name = "p_graph" if name == "p_graph_chain" else name
        if reasons.get(reason_name):
            scores[name] = 0.0


def probability_feature_values(
    scores: Mapping[str, float],
    reasons: Mapping[str, str | None],
) -> dict[str, object]:
    return {
        "p_attack_intelligence": safe_clamp(scores["p_attack_intelligence"]),
        "p_attack_intelligence_unavailable_reason": reasons["p_attack_intelligence"],
        "p_attention": safe_clamp(scores["p_attention"]),
        "p_behavior": safe_clamp(scores["p_behavior"]),
        "p_bucket": safe_clamp(scores["p_bucket"]),
        "p_bucket_unavailable_reason": reasons["p_bucket"],
        "p_chain": safe_clamp(scores["p_chain"]),
        "p_chain_unavailable_reason": reasons["p_chain"],
        "p_cluster": safe_clamp(scores["p_cluster"]),
        "p_cluster_unavailable_reason": reasons["p_cluster"],
        "p_engine": safe_clamp(scores["p_engine"]),
        "p_engine_unavailable_reason": reasons["p_engine"],
        "p_entropy": safe_clamp(scores["p_entropy"]),
        "p_evasion": safe_clamp(scores["p_evasion"]),
        "p_evasion_unavailable_reason": reasons["p_evasion"],
        "p_exec": safe_clamp(scores["p_exec"]),
        "p_graph": safe_clamp(scores["p_graph"]),
        "p_graph_chain": safe_clamp(scores["p_graph_chain"]),
        "p_graph_chain_unavailable_reason": reasons["p_graph"],
        "p_graph_unavailable_reason": reasons["p_graph"],
        "p_markov": safe_clamp(scores["p_markov"]),
        "p_markov_unavailable_reason": reasons["p_markov"],
        "p_mitre": safe_clamp(scores["p_mitre"]),
        "p_mitre_unavailable_reason": reasons["p_mitre"],
        "p_profile": safe_clamp(scores["p_profile"]),
        "p_profile_unavailable_reason": reasons["p_profile"],
        "p_temporal": safe_clamp(scores["p_temporal"]),
        "p_temporal_unavailable_reason": reasons["p_temporal"],
        "p_vector": safe_clamp(scores["p_vector"]),
        "p_vector_unavailable_reason": reasons["p_vector"],
        "p_yara": safe_clamp(scores["p_yara"]),
        "p_yara_unavailable_reason": reasons["p_yara"],
        "model_failure": None,
    }
