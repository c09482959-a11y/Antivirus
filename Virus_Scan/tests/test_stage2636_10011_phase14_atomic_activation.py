from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from Virus_Scan.detection.attack.activation import build_attack_activation_record
from Virus_Scan.detection.attack.alignment import TagStixAlignmentSpec
from Virus_Scan.detection.attack.config import AttackConfig
from Virus_Scan.detection.attack.contracts import AttackDatasetVersion
from Virus_Scan.detection.attack.domain_contracts import AttackRelationship, AttackTechnique
from Virus_Scan.detection.attack.download import refresh_repository
from Virus_Scan.detection.attack.implementations import AttackAnalyticImplementationSpec
from Virus_Scan.detection.attack.integrity import git_blob_sha1_bytes
from Virus_Scan.detection.attack.mapping.contracts import AttackTechniquePolicy
from Virus_Scan.detection.attack.named_contracts import (
    AttackAnalytic,
    AttackDataComponent,
    AttackDetectionStrategy,
    AttackLogSource,
    AttackLogSourceReference,
    AttackMutableElement,
)
from Virus_Scan.detection.attack.repository import build_repository_snapshot
from Virus_Scan.detection.attack.versioning import (
    ATTACK_MAPPING_POLICY_VERSION,
    ATTACK_REPOSITORY_SCHEMA_VERSION,
)
from Virus_Scan.orchestration import mitre_initialization
from Virus_Scan.runtime.api import release_mitre_runtime

_COMPONENT_STIX = "x-mitre-data-component--20000001-0000-4000-8000-000000000001"
_ANALYTIC_STIX = "x-mitre-analytic--20000002-0000-4000-8000-000000000002"
_STRATEGY_STIX = "x-mitre-detection-strategy--20000003-0000-4000-8000-000000000003"
_TECHNIQUE_STIX = "attack-pattern--20000004-0000-4000-8000-000000000004"
_RELATIONSHIP_STIX = "relationship--20000005-0000-4000-8000-000000000005"
_TIMESTAMP = "2026-05-12T14:00:00.000Z"


class _Response:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._read = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size: int = -1) -> bytes:
        if self._read:
            return b""
        self._read = True
        return self._data


def _version() -> AttackDatasetVersion:
    return AttackDatasetVersion(
        dataset_version="a" * 40,
        schema_version=ATTACK_REPOSITORY_SCHEMA_VERSION,
        source_ref="stage2636.10011-activation-test",
        expected_git_blob_sha1="a" * 40,
        computed_git_blob_sha1="a" * 40,
        local_sha256="b" * 64,
    )


def _objects(*, mutable: str = "Target process", description: str = "Detect access.", revoked: bool = False):
    component = AttackDataComponent(
        attack_id="DC0001", stix_id=_COMPONENT_STIX, name="Process Access",
        description="Process access telemetry.", domains=("enterprise-attack",),
        log_sources=(AttackLogSource("Sysmon", "EventCode=10"),),
        object_version="1.0", attack_spec_version="3.3.0", modified=_TIMESTAMP,
    )
    analytic = AttackAnalytic(
        attack_id="AN0001", stix_id=_ANALYTIC_STIX, name="Protected Process Access",
        description=description, platforms=("Windows",), domains=("enterprise-attack",),
        log_source_references=(
            AttackLogSourceReference(_COMPONENT_STIX, "Sysmon", "EventCode=10"),
        ),
        mutable_elements=(AttackMutableElement("TargetImage", mutable),),
        object_version="1.0", attack_spec_version="3.3.0", modified=_TIMESTAMP,
    )
    strategy = AttackDetectionStrategy(
        attack_id="DET0001", stix_id=_STRATEGY_STIX, name="Detect Protected Access",
        description="Strategy.", domains=("enterprise-attack",),
        analytic_stix_ids=(_ANALYTIC_STIX,), object_version="1.0",
        attack_spec_version="3.3.0", modified=_TIMESTAMP,
    )
    technique = AttackTechnique(
        attack_id="T1003", stix_id=_TECHNIQUE_STIX, name="OS Credential Dumping",
        tactic_ids=(), platforms=("Windows",), revoked=revoked,
    )
    relationship = AttackRelationship(
        stix_id=_RELATIONSHIP_STIX, relationship_type="detects",
        source_stix_id=_STRATEGY_STIX, target_stix_id=_TECHNIQUE_STIX,
    )
    return component, analytic, strategy, technique, relationship


def _snapshot(*, mutable: str = "Target process", description: str = "Detect access."):
    component, analytic, strategy, technique, relationship = _objects(
        mutable=mutable, description=description,
    )
    return build_repository_snapshot(
        version=_version(), objects=(component, analytic, strategy, technique),
        relationships=(relationship,),
    )


def _binding(snapshot):
    digest = snapshot.analytic_requirement_digest_by_id["AN0001"]
    alignment = TagStixAlignmentSpec(
        "lsass_access", ("DC0001",), ("host_telemetry",), ("Windows",),
        ("integrity_status", "observation_id", "root_observation_id", "target_identity"),
        ("test_sensor",), "exact", digest,
    )
    implementation = AttackAnalyticImplementationSpec(
        "official.t1003.an0001", "T1003", "DET0001", "AN0001",
        ("anchor:api_lsass_minidump",), ("DC0001",), "exact_official",
        "host_telemetry", ("Windows",), ("host_telemetry",), digest,
        "c" * 64, "confirmed_enabled",
    )
    policy = AttackTechniquePolicy(
        "T1003", (implementation.implementation_id,), "confirmed_enabled",
        ("host_telemetry",), "most_specific_wins", "credential_access",
        (digest,), "c" * 64, "", ATTACK_MAPPING_POLICY_VERSION,
    )
    return alignment, implementation, policy


def test_activation_keeps_unchanged_binding_and_ignores_description_only_edit() -> None:
    baseline = _snapshot()
    alignment, implementation, policy = _binding(baseline)
    record = build_attack_activation_record(
        baseline, alignments=(alignment,), implementations=(implementation,),
        policies=(policy,), calibrations=(),
    )
    assert record.active_alignment_ids == ("lsass_access",)
    assert record.active_implementation_ids == (implementation.implementation_id,)
    assert record.active_policy_ids == ("T1003",)
    description_only = _snapshot(description="Editorial text only.")
    repeated = build_attack_activation_record(
        description_only, alignments=(alignment,), implementations=(implementation,),
        policies=(policy,), calibrations=(),
    )
    assert repeated.active_policy_ids == ("T1003",)


def test_semantic_requirement_change_quarantines_only_affected_binding() -> None:
    baseline = _snapshot()
    alignment, implementation, policy = _binding(baseline)
    changed = _snapshot(mutable="Different target semantics")
    record = build_attack_activation_record(
        changed, alignments=(alignment,), implementations=(implementation,),
        policies=(policy,), calibrations=(),
    )
    assert record.quarantined_alignment_ids == ("lsass_access",)
    assert record.quarantined_implementation_ids == (implementation.implementation_id,)
    assert record.quarantined_policy_ids == ("T1003",)
    assert record.active_policy_ids == ()


def test_removed_strategy_quarantines_binding_and_revoked_technique_retires_policy() -> None:
    baseline = _snapshot()
    alignment, implementation, policy = _binding(baseline)
    component, analytic, _strategy, technique, _relationship = _objects()
    removed = build_repository_snapshot(
        version=_version(), objects=(component, analytic, technique), relationships=(),
    )
    removed_record = build_attack_activation_record(
        removed, alignments=(alignment,), implementations=(implementation,),
        policies=(policy,), calibrations=(),
    )
    assert removed_record.quarantined_implementation_ids == (implementation.implementation_id,)
    assert removed_record.quarantined_policy_ids == ("T1003",)

    revoked_technique = replace(technique, revoked=True)
    revoked = build_repository_snapshot(
        version=_version(), objects=(component, analytic, revoked_technique), relationships=(),
    )
    retired = build_attack_activation_record(
        revoked, alignments=(alignment,), implementations=(implementation,),
        policies=(policy,), calibrations=(),
    )
    assert retired.retired_policy_ids == ("T1003",)


def _download_bundle() -> bytes:
    return json.dumps({
        "type": "bundle", "id": "bundle--30000001-0000-4000-8000-000000000001",
        "objects": [{
            "type": "attack-pattern",
            "id": "attack-pattern--30000002-0000-4000-8000-000000000002",
            "name": "OS Credential Dumping", "description": "",
            "x_mitre_platforms": ["Windows"],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1003"}],
        }],
    }, sort_keys=True).encode()


def test_interrupted_state_activation_retains_prior_active_state(tmp_path: Path) -> None:
    bundle = _download_bundle()
    expected = git_blob_sha1_bytes(bundle)
    identity = json.dumps({
        "name": "enterprise-attack.json", "sha": expected,
        "download_url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    }).encode()
    prior_state = b'{"state_version":"prior"}\n'
    prior_index = b'{"index":"prior"}\n'
    (tmp_path / "mitre_state.json").write_bytes(prior_state)
    (tmp_path / "enterprise-attack-index.json").write_bytes(prior_index)
    responses = iter((_Response(identity), _Response(bundle)))
    with patch(
        "Virus_Scan.detection.attack.download.write_state",
        side_effect=OSError("interrupted activation"),
    ), pytest.raises(OSError, match="interrupted activation"):
        refresh_repository(
            tmp_path, AttackConfig(allow_download=True),
            opener=lambda *_args, **_kwargs: next(responses),
        )
    assert (tmp_path / "mitre_state.json").read_bytes() == prior_state
    assert (tmp_path / "enterprise-attack-index.json").read_bytes() == prior_index


def test_offline_restart_revalidates_activation_without_mutating_registries(tmp_path: Path) -> None:
    bundle = _download_bundle()
    expected = git_blob_sha1_bytes(bundle)
    root = tmp_path / "Mitre"
    root.mkdir()
    (root / f"enterprise-attack-v{expected}.json").write_bytes(bundle)
    before = tuple(sorted(mitre_initialization.__dict__))
    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}):
        runtime = mitre_initialization.initialize_mitre_from_args(SimpleNamespace(
            no_mitre=False, mitre_config=None, mitre_force_refresh=False,
            mitre_no_download=True, mitre_api_url=None, mitre_ref=None,
        ))
        assert runtime.available is True
        assert runtime.status["activation_state"] == "revalidated_from_local_cache"
        assert len(runtime.status["activation_digest"]) == 64
        assert runtime.status["activation_counts"]["active_policies"] == 0
        release_mitre_runtime()
    assert tuple(sorted(mitre_initialization.__dict__)) == before
