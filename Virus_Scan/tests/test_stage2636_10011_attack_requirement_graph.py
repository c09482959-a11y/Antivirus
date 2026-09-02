from __future__ import annotations

from dataclasses import fields, replace
from types import MappingProxyType

import pytest

from Virus_Scan.detection.attack.contracts import AttackDatasetVersion
from Virus_Scan.detection.attack.domain_contracts import (
    AttackRelationship,
    AttackTechnique,
)
from Virus_Scan.detection.attack.named_contracts import (
    AttackAnalytic,
    AttackDataComponent,
    AttackDetectionStrategy,
    AttackLogSource,
    AttackLogSourceReference,
    AttackMutableElement,
)
from Virus_Scan.detection.attack.repository import build_repository_snapshot
from Virus_Scan.detection.attack.versioning import ATTACK_REPOSITORY_SCHEMA_VERSION


_COMPONENT_STIX = "x-mitre-data-component--10000001-0000-4000-8000-000000000001"
_ANALYTIC_STIX = "x-mitre-analytic--10000002-0000-4000-8000-000000000002"
_STRATEGY_STIX = "x-mitre-detection-strategy--10000003-0000-4000-8000-000000000003"
_TECHNIQUE_STIX = "attack-pattern--10000004-0000-4000-8000-000000000004"
_SECOND_TECHNIQUE_STIX = "attack-pattern--10000005-0000-4000-8000-000000000005"
_RELATIONSHIP_STIX = "relationship--10000006-0000-4000-8000-000000000006"
_SECOND_RELATIONSHIP_STIX = "relationship--10000007-0000-4000-8000-000000000007"
_TIMESTAMP = "2025-10-21T14:00:00.000Z"


def _version() -> AttackDatasetVersion:
    return AttackDatasetVersion(
        dataset_version="a" * 40,
        schema_version=ATTACK_REPOSITORY_SCHEMA_VERSION,
        source_ref="stage2636.10011-requirement-test",
        expected_git_blob_sha1="a" * 40,
        computed_git_blob_sha1="a" * 40,
        local_sha256="b" * 64,
    )


def _component(
    *,
    attack_id: str = "DC0001",
    stix_identity: str = _COMPONENT_STIX,
    revoked: bool = False,
) -> AttackDataComponent:
    return AttackDataComponent(
        attack_id=attack_id,
        stix_id=stix_identity,
        name="Process Access",
        description="Process access telemetry.",
        domains=("enterprise-attack",),
        log_sources=(AttackLogSource("Sysmon", "EventCode=10"),),
        object_version="1.0",
        attack_spec_version="3.3.0",
        modified=_TIMESTAMP,
        revoked=revoked,
    )


def _analytic(
    *,
    component_stix_id: str = _COMPONENT_STIX,
    description: str = "Correlate access to a protected process.",
    mutable_description: str = "Tune the target process set.",
    revoked: bool = False,
) -> AttackAnalytic:
    return AttackAnalytic(
        attack_id="AN0001",
        stix_id=_ANALYTIC_STIX,
        name="Suspicious Process Access",
        description=description,
        platforms=("Windows",),
        domains=("enterprise-attack",),
        log_source_references=(
            AttackLogSourceReference(component_stix_id, "Sysmon", "EventCode=10"),
        ),
        mutable_elements=(
            AttackMutableElement("TargetImage", mutable_description),
        ),
        object_version="1.0",
        attack_spec_version="3.3.0",
        modified=_TIMESTAMP,
        revoked=revoked,
    )


def _strategy(
    *,
    analytic_stix_id: str = _ANALYTIC_STIX,
    domains: tuple[str, ...] = ("enterprise-attack",),
    revoked: bool = False,
) -> AttackDetectionStrategy:
    return AttackDetectionStrategy(
        attack_id="DET0001",
        stix_id=_STRATEGY_STIX,
        name="Detect Suspicious Process Access",
        description="Detect access associated with credential dumping.",
        domains=domains,
        analytic_stix_ids=(analytic_stix_id,),
        object_version="1.0",
        attack_spec_version="3.3.0",
        modified=_TIMESTAMP,
        revoked=revoked,
    )


def _technique(
    *,
    attack_id: str = "T1003",
    stix_identity: str = _TECHNIQUE_STIX,
    revoked: bool = False,
) -> AttackTechnique:
    return AttackTechnique(
        attack_id=attack_id,
        stix_id=stix_identity,
        name="OS Credential Dumping",
        tactic_ids=(),
        platforms=("Windows",),
        revoked=revoked,
    )


def _detects(
    *,
    source: str = _STRATEGY_STIX,
    target: str = _TECHNIQUE_STIX,
    stix_identity: str = _RELATIONSHIP_STIX,
    revoked: bool = False,
) -> AttackRelationship:
    return AttackRelationship(
        stix_id=stix_identity,
        relationship_type="detects",
        source_stix_id=source,
        target_stix_id=target,
        revoked=revoked,
    )


def _snapshot(
    *,
    component: AttackDataComponent | None = None,
    analytic: AttackAnalytic | None = None,
    strategy: AttackDetectionStrategy | None = None,
    technique: AttackTechnique | None = None,
    extra_objects: tuple[object, ...] = (),
    relationships: tuple[AttackRelationship, ...] | None = None,
):
    objects = (
        _component() if component is None else component,
        _analytic() if analytic is None else analytic,
        _strategy() if strategy is None else strategy,
        _technique() if technique is None else technique,
        *extra_objects,
    )
    return build_repository_snapshot(
        version=_version(),
        objects=objects,
        relationships=(_detects(),) if relationships is None else relationships,
    )


def test_requirement_graph_publishes_exact_immutable_indexes() -> None:
    retired_component = _component(
        attack_id="DC0002",
        stix_identity="x-mitre-data-component--10000008-0000-4000-8000-000000000008",
        revoked=True,
    )
    snapshot = _snapshot(extra_objects=(retired_component,))
    assert snapshot.data_component_by_attack_id == {"DC0001": snapshot.by_attack_id["DC0001"]}
    assert snapshot.data_component_by_stix_id == {_COMPONENT_STIX: snapshot.by_attack_id["DC0001"]}
    assert snapshot.analytic_by_attack_id == {"AN0001": snapshot.by_attack_id["AN0001"]}
    assert snapshot.analytic_by_stix_id == {_ANALYTIC_STIX: snapshot.by_attack_id["AN0001"]}
    assert snapshot.strategy_by_attack_id == {"DET0001": snapshot.by_attack_id["DET0001"]}
    assert snapshot.strategy_by_stix_id == {_STRATEGY_STIX: snapshot.by_attack_id["DET0001"]}
    assert snapshot.analytics_by_strategy_id == {"DET0001": (snapshot.by_attack_id["AN0001"],)}
    assert snapshot.data_components_by_analytic_id == {"AN0001": (snapshot.by_attack_id["DC0001"],)}
    assert snapshot.strategies_by_technique_id == {"T1003": (snapshot.by_attack_id["DET0001"],)}
    assert snapshot.techniques_by_strategy_id == {"DET0001": (snapshot.by_attack_id["T1003"],)}
    assert len(snapshot.analytic_requirement_digest_by_id["AN0001"]) == 64
    assert type(snapshot.data_component_by_attack_id) is MappingProxyType
    assert "DC0002" not in snapshot.data_component_by_attack_id
    assert snapshot.to_record()["active_requirement_counts"] == {
        "data_components": 1,
        "analytics": 1,
        "detection_strategies": 1,
        "analytic_requirement_digests": 1,
    }


def test_requirement_graph_rejects_missing_strategy_analytic() -> None:
    missing = "x-mitre-analytic--10000009-0000-4000-8000-000000000009"
    with pytest.raises(ValueError, match="strategy_analytic_missing"):
        _snapshot(strategy=_strategy(analytic_stix_id=missing))


def test_requirement_graph_rejects_missing_or_inactive_data_component() -> None:
    missing = "x-mitre-data-component--10000009-0000-4000-8000-000000000009"
    with pytest.raises(ValueError, match="analytic_component_missing"):
        _snapshot(analytic=_analytic(component_stix_id=missing))
    with pytest.raises(ValueError, match="analytic_component_missing"):
        _snapshot(component=_component(revoked=True))


def test_requirement_graph_rejects_invalid_detects_direction_and_lifecycle() -> None:
    with pytest.raises(ValueError, match="detects_direction_invalid"):
        _snapshot(relationships=(_detects(source=_TECHNIQUE_STIX, target=_STRATEGY_STIX),))
    with pytest.raises(ValueError, match="detects_endpoint_inactive"):
        _snapshot(strategy=_strategy(revoked=True))
    with pytest.raises(ValueError, match="detects_endpoint_inactive"):
        _snapshot(technique=_technique(revoked=True))
    with pytest.raises(ValueError, match="detects_endpoint_inactive"):
        _snapshot(strategy=_strategy(domains=("mobile-attack",)))


def test_requirement_graph_requires_exactly_one_technique_per_strategy() -> None:
    with pytest.raises(ValueError, match="detects_cardinality_invalid"):
        _snapshot(relationships=())
    second = _technique(attack_id="T1055", stix_identity=_SECOND_TECHNIQUE_STIX)
    relationships = (
        _detects(),
        _detects(
            target=_SECOND_TECHNIQUE_STIX,
            stix_identity=_SECOND_RELATIONSHIP_STIX,
        ),
    )
    with pytest.raises(ValueError, match="detects_cardinality_invalid"):
        _snapshot(extra_objects=(second,), relationships=relationships)


def test_requirement_digest_changes_only_with_semantic_requirements() -> None:
    baseline = _snapshot()
    reordered = build_repository_snapshot(
        version=_version(),
        objects=tuple(reversed(baseline.objects)),
        relationships=tuple(reversed(baseline.relationships)),
    )
    assert baseline.analytic_requirement_digest_by_id == reordered.analytic_requirement_digest_by_id

    description_only = _snapshot(analytic=_analytic(description="Editorial wording only."))
    assert baseline.digest != description_only.digest
    assert baseline.analytic_requirement_digest_by_id == description_only.analytic_requirement_digest_by_id

    semantic_change = _snapshot(analytic=_analytic(mutable_description="Different tuning semantics."))
    assert baseline.analytic_requirement_digest_by_id != semantic_change.analytic_requirement_digest_by_id


def test_repository_rejects_forged_requirement_index() -> None:
    snapshot = _snapshot()
    values = {field.name: getattr(snapshot, field.name) for field in fields(snapshot)}
    for key, value in tuple(values.items()):
        if type(value) is MappingProxyType:
            values[key] = dict(value)
    values["analytic_requirement_digest_by_id"] = {"AN0001": "0" * 64}
    with pytest.raises((TypeError, ValueError), match="requirement_digest_index_invalid"):
        type(snapshot)(**values)
