"""Exact supplied-resource integrity and engine-independent YARA→MITRE handoff."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from types import ModuleType, SimpleNamespace

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.attack.integrity import git_blob_sha1_bytes, sha256_bytes
from Virus_Scan.detection.attack.stix_importer import import_stix_bundle
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import current_attack_mapping_fixture
from Virus_Scan.tests.support.canonical_yara_fixtures import candidate_mitre_alignment
from Virus_Scan.detection.scoring.adaptive.evidence_projection_components import (
    mitre_probability_component,
)
from Virus_Scan.detection.evidence.yara_assimilation import assimilate_reviewed_yara_evidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import (
    normalize_tag_evidence,
)
from Virus_Scan.runtime.yara_rules_state import YaraRulesSnapshot
from Virus_Scan.yara.cache_identity import build_cache_identity
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.contracts import YaraRuleLoadResult
from Virus_Scan.yara.match import yara_scan
from Virus_Scan.yara.rule_archive import validate_rule_archive
from Virus_Scan.yara.source import custom_rule_source

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_MITRE_BUNDLE = _REPOSITORY_ROOT / "Mitre" / "enterprise-attack.json"
_YARA_CORE = _REPOSITORY_ROOT / "Yara" / "yara-forge-rules-core.zip"
_YARA_EXTENDED = _REPOSITORY_ROOT / "Yara" / "yara-forge-rules-extended.zip"
_MITRE_SHA256 = "bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3"
_YARA_CORE_SHA256 = "3ad85d8518e5e968d930c93dadae9dcd7d215d0911d8d8f02717f15922c8529f"
_YARA_EXTENDED_SHA256 = "756bd295a87603d78f1c879ecb7d217c91c1bcb03461c34e604fa20a4a0acae5"
_MITRE_REPOSITORY_DIGEST = "96da129230304ea566cfa7dc7f0bf94da7f6b01bb41fad810943ff1d98a840b3"


class _Rules:
    rule_id = "stage2636_external_resource_encoded_powershell"

    def match(self, path: str) -> list[object]:
        assert Path(path).is_file()
        return [SimpleNamespace(
            rule=self.rule_id,
            namespace="ignored_single_member_namespace",
            meta={"id": "stage2636-external-resource", "logic_hash": "e" * 64},
            tags=["stage2636_test"],
        )]


def _module() -> ModuleType:
    module = ModuleType("yara")
    module.__version__ = "4.5.2-contract-test"
    return module


def test_supplied_mitre_and_yara_resources_are_exact_and_parseable() -> None:
    mitre_data = _MITRE_BUNDLE.read_bytes()
    assert sha256(mitre_data).hexdigest() == _MITRE_SHA256
    snapshot = import_stix_bundle(
        mitre_data,
        dataset_version=git_blob_sha1_bytes(mitre_data),
        source_ref="stage2636.11006-supplied-resource-test",
        expected_git_blob_sha1=git_blob_sha1_bytes(mitre_data),
        computed_git_blob_sha1=git_blob_sha1_bytes(mitre_data),
        local_sha256=sha256_bytes(mitre_data),
    )
    assert snapshot.digest == _MITRE_REPOSITORY_DIGEST

    config = YaraConfig()
    core_members = validate_rule_archive(_YARA_CORE, config)
    extended_members = validate_rule_archive(_YARA_EXTENDED, config)
    assert sha256(_YARA_CORE.read_bytes()).hexdigest() == _YARA_CORE_SHA256
    assert sha256(_YARA_EXTENDED.read_bytes()).hexdigest() == _YARA_EXTENDED_SHA256
    assert tuple(item.name for item in core_members) == (
        "packages/core/yara-rules-core.yar",
    )
    assert tuple(item.name for item in extended_members) == (
        "packages/extended/yara-rules-extended.yar",
    )


def test_supplied_yara_identity_reaches_mitre_candidate_handoff(
    tmp_path: Path,
) -> None:
    source = custom_rule_source(
        _YARA_CORE,
        YaraConfig(light_expected_sha256=_YARA_CORE_SHA256),
        package_kind="core",
    )
    identity = build_cache_identity(source, _module())
    load_result = YaraRuleLoadResult(
        "custom_verified", True,
        len(source.members), len(source.members), 0,
        0.95, (), "",
    )
    rules_snapshot = YaraRulesSnapshot(
        rules=_Rules(),
        loaded_count=len(source.members),
        source_path=str(_YARA_CORE),
        source=source,
        identity=identity,
        load_result=load_result,
    )
    sample = tmp_path / "safe_fixture.ps1"
    sample.write_text(
        "# NON-EXECUTABLE synthetic encoded PowerShell marker\n",
        encoding="utf-8",
    )
    result = yara_scan(sample, compiled_rules=rules_snapshot)
    hit = result.hits[0]
    assert hit.verified is True
    assert hit.rule_identity.rule_source_digest == _YARA_CORE_SHA256

    alignment = candidate_mitre_alignment(
        hit, alignment_id="stage2636.11006.external-resource-handoff",
    )
    tags = assimilate_reviewed_yara_evidence(
        normalize_tag_evidence(()),
        result,
        alignments=(alignment,),
        platform="windows",
        repository_digest=alignment.repository_digest,
    )
    probability, _reason, evidence = mitre_probability_component(
        current_attack_mapping_fixture(
            tags, ChainEvidence("stage2636_11006_empty", "empty-digest"),
        )
    )
    assert probability == 0.0
    assert any(
        record.modality == "yara_match"
        and record.root_observation_id == hit.root_observation_id
        for record in tags.records
    )
    assert evidence["confirmed"] == ()
