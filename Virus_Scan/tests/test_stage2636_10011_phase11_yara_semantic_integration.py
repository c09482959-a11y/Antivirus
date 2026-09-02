"""Phase 11 canonical YARA provenance and semantic-authority tests."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from types import ModuleType, SimpleNamespace
import zipfile

import pytest

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.detection_observation import (
    DetectionObservation,
    ObservationSourceLocation,
)
from Virus_Scan.contracts.yara_hits import YaraHit, YaraScanResult
from Virus_Scan.detection.attack.yara_alignment import (
    YaraObservationAlignmentSpec,
    canonical_yara_alignment_platform,
    project_yara_observations,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence import (
    compute_attack_intelligence,
)
from Virus_Scan.detection.evidence.yara_assimilation import assimilate_reviewed_yara_evidence
from Virus_Scan.detection.scoring.yara.context_evidence import generic_yara_evidence_context
from Virus_Scan.detection.scoring.adaptive.evidence_projection_components import (
    mitre_probability_component,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import (
    normalize_tag_evidence,
)
from Virus_Scan.runtime.yara_rules_state import YaraRulesSnapshot
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import current_attack_mapping_fixture
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.tests.support.canonical_yara_fixtures import (
    candidate_mitre_alignment,
    family_alignment,
)
from Virus_Scan.yara.cache_identity import build_cache_identity
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.contracts import YaraRuleLoadResult
from Virus_Scan.yara.match import yara_scan, yara_scan_with_optional_zip
from Virus_Scan.yara.source import custom_rule_source


class _Rules:
    def __init__(self, rule_id: str = "stage2636_exfiltration") -> None:
        self.rule_id = rule_id
        self.paths: list[str] = []

    def match(self, path: str) -> list[object]:
        self.paths.append(path)
        return [SimpleNamespace(
            rule=self.rule_id,
            namespace="ignored_single_member_namespace",
            meta={"id": "stage2636-test-id", "logic_hash": "e" * 64},
            tags=["stage2636_test"],
        )]


def _module() -> ModuleType:
    module = ModuleType("yara")
    module.__version__ = "4.5.2"
    return module


def _verified_snapshot(tmp_path: Path, rules: object | None = None) -> YaraRulesSnapshot:
    rule_path = tmp_path / "rules.yar"
    rule_path.write_text("rule Good { condition: true }", encoding="utf-8")
    digest = sha256(rule_path.read_bytes()).hexdigest()
    source = custom_rule_source(
        rule_path, YaraConfig(custom_rule_expected_sha256=digest),
        package_kind="custom",
    )
    identity = build_cache_identity(source, _module())
    load_result = YaraRuleLoadResult(
        "custom_verified", True, 1, 1, 0, 0.95, (), "",
    )
    return YaraRulesSnapshot(
        rules=rules if rules is not None else _Rules(),
        loaded_count=1,
        source_path=str(rule_path),
        source=source,
        identity=identity,
        load_result=load_result,
    )


def _candidate_alignment(hit: YaraHit) -> YaraObservationAlignmentSpec:
    return candidate_mitre_alignment(
        hit, alignment_id="phase11.encoded_powershell",
    )


def test_verified_matcher_emits_physical_integrity_bound_hit(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    snapshot = _verified_snapshot(tmp_path)
    first = yara_scan(sample, compiled_rules=snapshot)
    repeated = yara_scan(sample, compiled_rules=snapshot)
    assert type(first) is YaraScanResult
    assert first == repeated
    assert first.status == "complete"
    assert first.retained_match_count == 1
    hit = first.hits[0]
    assert type(hit) is YaraHit
    assert hit.verified is True
    assert hit.rule_identity.rule_source_digest == snapshot.source.archive_sha256
    assert hit.rule_identity.compiled_cache_digest == snapshot.identity.digest
    assert hit.rule_identity.logic_hash == "e" * 64
    assert hit.artifact_identity == "content_sha256:" + sha256(b"sample").hexdigest()
    assert hit.source_location.locator == sample.as_posix()
    assert hit.source_location.event_id == hit.rule_identity.digest
    assert hit.root_observation_id.startswith("obs_")


def test_raw_rule_carrier_is_unverified_and_cannot_project(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    result = yara_scan(sample, compiled_rules=_Rules())
    assert result.status == "complete"
    assert result.hits[0].integrity_status == "unverified"
    assert project_yara_observations(
        result, alignments=(), platform="windows",
    ) == ()


def test_candidate_alignment_is_context_only_and_never_scores(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    result = yara_scan(sample, compiled_rules=_verified_snapshot(tmp_path))
    alignment = _candidate_alignment(result.hits[0])
    observations = project_yara_observations(
        result, alignments=(alignment,), platform="windows",
        repository_digest=alignment.repository_digest,
    )
    assert len(observations) == 1
    assert observations[0].directness == "context"
    assert observations[0].root_observation_id == result.hits[0].root_observation_id
    tags = assimilate_reviewed_yara_evidence(
        normalize_tag_evidence(()),
        result,
        alignments=(alignment,),
        platform="windows",
        repository_digest=alignment.repository_digest,
    )
    probability, _reason, evidence = mitre_probability_component(
        current_attack_mapping_fixture(
            tags, ChainEvidence("phase11_empty", "empty-digest"),
        )
    )
    assert probability == 0.0
    assert any(
        record.modality == "yara_match"
        and record.root_observation_id == result.hits[0].root_observation_id
        for record in tags.records
    )
    assert evidence["confirmed"] == ()


def test_mitre_component_uses_canonical_platform_from_tag_evidence(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    result = yara_scan(sample, compiled_rules=_verified_snapshot(tmp_path))
    alignment = _candidate_alignment(result.hits[0])
    tags = normalize_tag_evidence((DetectionObservation.create(
        tag="powershell_exec",
        producer_id="phase11_platform_fixture",
        stage_id="static_analysis",
        modality="static_structure",
        platform="Windows",
        artifact_identity="sha256:phase11-platform-fixture",
        source_location=ObservationSourceLocation(
            "fixture_event", locator="sample.bin", event_id="platform-context",
        ),
        integrity_status="verified",
        directness="direct",
        confidence=1.0,
    ),))

    platform = canonical_yara_alignment_platform(tags)
    tags = assimilate_reviewed_yara_evidence(
        tags, result, alignments=(alignment,), platform=platform,
        repository_digest=alignment.repository_digest,
    )
    probability, _reason, evidence = mitre_probability_component(
        current_attack_mapping_fixture(
            tags, ChainEvidence("phase11_empty", "empty-digest"),
        )
    )

    assert alignment.platforms == ("windows",)
    assert probability == 0.0
    assert any(record.modality == "yara_match" for record in tags.records)
    assert evidence["confirmed"] == ()


def test_mitre_component_does_not_guess_conflicting_tag_platforms(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    result = yara_scan(sample, compiled_rules=_verified_snapshot(tmp_path))
    alignment = _candidate_alignment(result.hits[0])
    observations = tuple(
        DetectionObservation.create(
            tag=tag,
            producer_id="phase11_platform_fixture",
            stage_id="static_analysis",
            modality="static_structure",
            platform=platform,
            artifact_identity="sha256:phase11-platform-fixture",
            source_location=ObservationSourceLocation(
                "fixture_event",
                locator="sample.bin",
                event_id="platform-context-" + platform.casefold(),
            ),
            integrity_status="verified",
            directness="direct",
            confidence=1.0,
        )
        for tag, platform in (
            ("powershell_exec", "Windows"),
            ("network_download", "Linux"),
        )
    )
    tags = normalize_tag_evidence(observations)

    assert canonical_yara_alignment_platform(tags) == ""
    assimilated = assimilate_reviewed_yara_evidence(
        tags, result, alignments=(alignment,), platform="",
        repository_digest=alignment.repository_digest,
    )
    probability, _reason, _evidence = mitre_probability_component(
        current_attack_mapping_fixture(
            assimilated, ChainEvidence("phase11_empty", "empty-digest"),
        )
    )

    assert assimilated is tags
    assert probability == 0.0
    assert not any(record.modality == "yara_match" for record in assimilated.records)


def test_one_yara_root_is_shared_without_independent_double_counting(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    result = yara_scan(sample, compiled_rules=_verified_snapshot(tmp_path))
    hit = result.hits[0]
    alignment = _candidate_alignment(hit)
    generic_context = generic_yara_evidence_context(result)
    assert generic_context.rule_names == (hit.rule_identity.rule_name,)
    assert generic_context.root_observation_ids == (hit.root_observation_id,)
    assert generic_context.probability_authority is False
    observations = project_yara_observations(
        result, alignments=(alignment,), platform="windows",
        repository_digest=alignment.repository_digest,
    )
    assert observations[0].root_observation_id == hit.root_observation_id
    attack = compute_attack_intelligence(
        physical_tag_evidence(("collection", "http_upload")),
        result,
        yara_family_alignments=(family_alignment(hit),),
    )
    record = next(
        item for item in attack["classifier_records"]
        if item["family"] == "exfiltration"
    )
    assert record["matched_root_evidence_ids"].count(hit.root_observation_id) == 1


def test_zip_member_identity_preserves_relative_archive_path(tmp_path: Path) -> None:
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr("first/payload.bin", b"one")
        stream.writestr("second/payload.bin", b"two")
    result = yara_scan_with_optional_zip(
        archive, compiled_rules=_verified_snapshot(tmp_path, _Rules("zip_rule")),
    )
    assert result.archive_member_count == 2
    assert result.scanned_member_count == 2
    assert tuple(sorted(
        hit.source_location.archive_member for hit in result.hits
    )) == ("first/payload.bin", "second/payload.bin")
    assert len({hit.root_observation_id for hit in result.hits}) == 2


def test_alignment_registry_rejects_duplicate_rule_authority(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    result = yara_scan(sample, compiled_rules=_verified_snapshot(tmp_path))
    first = _candidate_alignment(result.hits[0])
    second_record = first.to_record()
    second_record["alignment_id"] = "phase11.duplicate"
    second_record["tag_id"] = "powershell_exec"
    second = YaraObservationAlignmentSpec(**second_record)
    with pytest.raises(ValueError, match="yara_alignment_duplicate_rule_identity"):
        project_yara_observations(
            result,
            alignments=(first, second),
            platform="windows",
            repository_digest=first.repository_digest,
        )


class _HostileYaraBoundary:
    touched: list[str] = []

    @classmethod
    def reset(cls) -> None:
        cls.touched.clear()

    def __bool__(self) -> bool:
        type(self).touched.append("__bool__")
        return True

    def __iter__(self):
        type(self).touched.append("__iter__")
        return iter(())

    def __str__(self) -> str:
        type(self).touched.append("__str__")
        return "hostile"


def test_unverified_yara_cannot_affect_mitre_probability(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    result = yara_scan(sample, compiled_rules=_Rules())
    base = normalize_tag_evidence(())
    tags = assimilate_reviewed_yara_evidence(
        base, result, alignments=(), platform="windows", repository_digest="4" * 64,
    )
    probability, _reason, evidence = mitre_probability_component(
        current_attack_mapping_fixture(
            tags, ChainEvidence("phase11_empty", "empty-digest"),
        )
    )
    assert tags is base
    assert probability == 0.0
    assert evidence["confirmed"] == ()


def test_hostile_yara_boundaries_reject_without_hooks() -> None:
    hostile = _HostileYaraBoundary()
    _HostileYaraBoundary.reset()
    assert project_yara_observations(
        hostile, alignments=(), platform="windows", repository_digest="4" * 64,
    ) == ()
    with pytest.raises(TypeError, match="yara_alignment_registry_invalid"):
        project_yara_observations(
            (), alignments=hostile, platform="windows", repository_digest="4" * 64,  # type: ignore[arg-type]
        )
    assert _HostileYaraBoundary.touched == []


def test_runtime_snapshot_opaque_hostile_provenance_fails_closed_without_hooks(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    hostile = _HostileYaraBoundary()
    _HostileYaraBoundary.reset()
    snapshot = YaraRulesSnapshot(
        rules=_Rules(),
        loaded_count=1,
        source=hostile,
        identity=hostile,
        load_result=hostile,
    )
    result = yara_scan(sample, compiled_rules=snapshot)
    hit = result.hits[0]
    assert hit.integrity_status == "unverified"
    assert hit.source_trust == "unavailable"
    assert hit.rule_identity.rule_source_digest == ""
    assert hit.rule_identity.compiled_cache_digest == ""
    assert _HostileYaraBoundary.touched == []
