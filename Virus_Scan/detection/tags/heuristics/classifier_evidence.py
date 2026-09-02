"""Canonical provenance-aware scoring primitives for tag classifiers."""

from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float
from Virus_Scan.contracts.tag_evidence import (
    TagEvidenceRecord,
    active_tag_evidence_records,
    positive_tag_group_root_matches,
)
from Virus_Scan.contracts.tag_taxonomy import TAG_CLASS_ATOMIC_OBSERVATION
from Virus_Scan.detection.registries.tag_taxonomy_registry import tag_class_for
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.utils.tagging import canonical_tag_name, ordered_unique_tags

CLASSIFIER_EVIDENCE_KINDS = frozenset({
    "observed", "normalized", "derived", "composite",
})


def _classifier_authority_record(record: object) -> bool:
    """Return whether one record may carry classifier evidence authority."""
    return (
        type(record) is TagEvidenceRecord
        and record.evidence_kind in CLASSIFIER_EVIDENCE_KINDS
        and record.polarity == "positive"
        and tag_class_for(record.canonical_tag_id) == TAG_CLASS_ATOMIC_OBSERVATION
    )


def classifier_authority_records(bundle: TagEvidence) -> tuple[TagEvidenceRecord, ...]:
    """Return active atomic factual records; context remains publication-only."""
    return tuple(
        record for record in active_tag_evidence_records(bundle.records)
        if _classifier_authority_record(record)
    )


def classifier_tag_evidence(value: object) -> TagEvidence:
    """Require the canonical immutable bundle at the classifier boundary."""
    if type(value) is not TagEvidence:
        raise TypeError("classifier_tag_evidence_bundle_required")
    return value


def classifier_tagset(bundle: TagEvidence) -> frozenset[str]:
    """Return the atomic factual projection authorized for classifiers."""
    return frozenset(
        canonical_tag_name(record.canonical_tag_id)
        for record in classifier_authority_records(bundle)
        if canonical_tag_name(record.canonical_tag_id)
    )


def classifier_root_matches(
    bundle: TagEvidence,
    options: object,
) -> tuple[tuple[str, str], ...]:
    """Return one deterministic semantic label per matching evidence root."""
    wanted = frozenset(
        canonical_tag_name(value)
        for value in ordered_unique_tags(options)
        if canonical_tag_name(value)
    )
    if not wanted:
        return ()
    per_root: dict[str, str] = {}
    for record in classifier_authority_records(bundle):
        labels = frozenset((
            canonical_tag_name(record.canonical_tag_id),
            canonical_tag_name(record.publication_name),
        ))
        matched = sorted((labels & wanted) - {""})
        if matched:
            per_root.setdefault(record.root_observation_id, matched[0])
    return tuple(sorted(per_root.items()))


def classifier_rule_matches(
    bundle: TagEvidence,
    groups: object,
) -> tuple[tuple[str, str], ...]:
    """Return a complete distinct-root match for one semantic rule."""
    if type(groups) not in (tuple, list) or not groups:
        return ()
    matches = positive_tag_group_root_matches(
        classifier_authority_records(bundle),
        groups,
        allowed_evidence_kinds=CLASSIFIER_EVIDENCE_KINDS,
    )
    return matches if len(matches) == len(groups) else ()


def add_classifier_contribution(
    contributions: dict[tuple[str, ...], tuple[float, str]],
    matches: object,
    points: float,
    label: str,
) -> None:
    """Keep one maximum contribution for each exact evidence-root set."""
    if type(matches) not in (tuple, list) or not matches or points <= 0.0:
        return
    roots = tuple(sorted({
        match[0]
        for match in matches
        if type(match) in (tuple, list) and len(match) == 2 and type(match[0]) is str
    }))
    if not roots:
        return
    current = contributions.get(roots)
    candidate = (float(points), str.__str__(label))
    if current is None or candidate[0] > current[0]:
        contributions[roots] = candidate


def add_classifier_root_contributions(
    contributions: dict[tuple[str, ...], tuple[float, str]],
    matches: object,
    points_per_root: float,
) -> None:
    """Add at most one contribution for every independent matching root."""
    if type(matches) not in (tuple, list):
        return
    for match in matches:
        if type(match) not in (tuple, list) or len(match) != 2:
            continue
        root_id, label = match
        if type(root_id) is not str or type(label) is not str:
            continue
        add_classifier_contribution(
            contributions, ((root_id, label),), points_per_root, label,
        )


@dataclass(frozen=True, slots=True)
class ClassifierContribution:
    """One immutable score contribution attributed to exact evidence roots."""

    root_observation_ids: tuple[str, ...]
    points: float
    label: str

    def __post_init__(self) -> None:
        source_roots = (
            tuple(self.root_observation_ids)
            if type(self.root_observation_ids) in (tuple, list)
            else ()
        )
        roots = tuple(sorted({
            root for root in source_roots if type(root) is str and root
        }))
        points, _reason = no_hook_finite_float(
            self.points,
            default=0.0,
            minimum=0.0,
            reason="invalid_classifier_contribution_points",
            non_finite_reason="non_finite_classifier_contribution_points",
        )
        label = str.__str__(self.label) if type(self.label) is str else ""
        object.__setattr__(self, "root_observation_ids", roots)
        object.__setattr__(self, "points", points)
        object.__setattr__(self, "label", label)


@dataclass(frozen=True, slots=True)
class ClassifierEvidenceResult:
    """Canonical classifier result retaining root attribution for fusion."""

    contributions: tuple[ClassifierContribution, ...]
    informational_hits: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        source_contributions = (
            tuple(self.contributions)
            if type(self.contributions) in (tuple, list)
            else ()
        )
        source_informational = (
            tuple(self.informational_hits)
            if type(self.informational_hits) in (tuple, list)
            else ()
        )
        contributions = tuple(
            item for item in source_contributions
            if type(item) is ClassifierContribution
        )
        informational = tuple(sorted({
            str.__str__(item) for item in source_informational
            if type(item) is str and item
        }))
        object.__setattr__(self, "contributions", contributions)
        object.__setattr__(self, "informational_hits", informational)

    @property
    def score(self) -> float:
        return sum(contribution.points for contribution in self.contributions)

    @property
    def hits(self) -> tuple[str, ...]:
        return tuple(sorted({
            *(contribution.label for contribution in self.contributions if contribution.label),
            *self.informational_hits,
        }))


def classifier_result(
    contributions: dict[tuple[str, ...], tuple[float, str]],
) -> ClassifierEvidenceResult:
    """Return immutable root-attributed contributions in deterministic order."""
    return ClassifierEvidenceResult(tuple(
        ClassifierContribution(
            root_observation_ids=roots, points=value[0], label=value[1],
        )
        for roots, value in sorted(dict.items(contributions))
        if roots and value[0] > 0.0
    ))


def merge_non_overlapping_classifier_contributions(
    results: object,
) -> ClassifierEvidenceResult:
    """Select one maximum deterministic contribution for every evidence root.

    A contribution that cites multiple roots is a correlated interpretation of
    those roots, not additional independent observations. Once selected, none
    of its roots may support another selected contribution.
    """
    if type(results) not in (tuple, list):
        return ClassifierEvidenceResult(())
    candidates: dict[tuple[str, ...], ClassifierContribution] = {}
    informational_hits: set[str] = set()
    for result in results:
        if type(result) is not ClassifierEvidenceResult:
            continue
        informational_hits.update(result.informational_hits)
        for contribution in result.contributions:
            previous = candidates.get(contribution.root_observation_ids)
            if (
                previous is None
                or contribution.points > previous.points
                or (
                    contribution.points == previous.points
                    and contribution.label < previous.label
                )
            ):
                candidates[contribution.root_observation_ids] = contribution
    ordered = sorted(
        candidates.values(),
        key=lambda contribution: (
            -contribution.points,
            -len(contribution.root_observation_ids),
            contribution.root_observation_ids,
            contribution.label,
        ),
    )
    used_roots: set[str] = set()
    selected: list[ClassifierContribution] = []
    for contribution in ordered:
        roots = set(contribution.root_observation_ids)
        if not roots or roots & used_roots:
            continue
        selected.append(contribution)
        used_roots.update(roots)
    return ClassifierEvidenceResult(
        tuple(sorted(
            selected,
            key=lambda contribution: (
                contribution.root_observation_ids, contribution.label,
            ),
        )),
        informational_hits=tuple(sorted(informational_hits)),
    )


__all__ = (
    "ClassifierContribution",
    "ClassifierEvidenceResult",
    "CLASSIFIER_EVIDENCE_KINDS",
    "add_classifier_contribution",
    "classifier_authority_records",
    "add_classifier_root_contributions",
    "classifier_result",
    "classifier_root_matches",
    "classifier_rule_matches",
    "classifier_tag_evidence",
    "classifier_tagset",
    "merge_non_overlapping_classifier_contributions",
)
