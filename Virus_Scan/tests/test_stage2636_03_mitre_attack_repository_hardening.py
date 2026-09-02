from __future__ import annotations
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import current_attack_mapping_fixture

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.attack.api import official_attack_probability_evidence
from Virus_Scan.detection.attack.config import AttackConfig
from Virus_Scan.detection.attack.domain_contracts import (
    AttackMitigation,
    AttackSubTechnique,
    AttackTactic,
    AttackTechnique,
)
from Virus_Scan.detection.attack.download import refresh_repository
from Virus_Scan.detection.attack.integrity import git_blob_sha1_bytes, sha256_bytes
from Virus_Scan.detection.attack.repository import subtechniques_by_parent, techniques_by_tactic
from Virus_Scan.detection.attack.stix_importer import import_stix_bundle
from Virus_Scan.detection.scoring.adaptive.evidence_projection_components import mitre_probability_component
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.orchestration.mitre_initialization import initialize_mitre_from_args
from Virus_Scan.runtime.api import ResourceLockSet, configure_mitre_runtime, release_mitre_runtime


def _id(kind: str, number: int) -> str:
    return f"{kind}--{number:08x}-0000-4000-8000-{number:012x}"


def _bundle(*, label: str = "A", orphan: bool = False) -> bytes:
    objects: list[dict[str, object]] = [
        {
            "type": "x-mitre-tactic", "id": _id("x-mitre-tactic", 1),
            "name": "Execution", "description": "", "x_mitre_shortname": "execution",
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}],
        },
        {
            "type": "attack-pattern", "id": _id("attack-pattern", 2),
            "name": "PowerShell " + label, "description": "", "x_mitre_platforms": ["Windows"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}],
        },
    ]
    if not orphan:
        objects.insert(1, {
            "type": "attack-pattern", "id": _id("attack-pattern", 3),
            "name": "Command Interpreter", "description": "", "x_mitre_platforms": ["Windows"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
        })
    return json.dumps({"type": "bundle", "id": _id("bundle", 4), "objects": objects}, sort_keys=True).encode()


def _snapshot(payload: bytes | None = None):
    data = _bundle() if payload is None else payload
    identity = git_blob_sha1_bytes(data)
    return import_stix_bundle(
        data, dataset_version=identity, source_ref="test-ref",
        expected_git_blob_sha1=identity, computed_git_blob_sha1=identity,
        local_sha256=sha256_bytes(data),
    )


class _Response:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size: int = -1) -> bytes:
        payload, self.payload = self.payload, b""
        return payload


class _TrapDict(dict):
    called = False

    def items(self):
        type(self).called = True
        raise AssertionError("caller hook invoked")

    def __iter__(self):
        type(self).called = True
        raise AssertionError("caller hook invoked")


def test_repository_has_explicit_tactic_technique_subtechnique_and_indexes() -> None:
    snapshot = _snapshot()
    assert type(snapshot.tactics[0]) is AttackTactic
    assert type(snapshot.by_attack_id["T1059"]) is AttackTechnique
    assert type(snapshot.by_attack_id["T1059.001"]) is AttackSubTechnique
    assert techniques_by_tactic(snapshot, "TA0002") == snapshot.techniques
    assert subtechniques_by_parent(snapshot, "T1059") == (snapshot.by_attack_id["T1059.001"],)


def test_deprecated_legacy_mitigation_is_preserved_by_stix_without_shadowing_technique() -> None:
    payload = json.loads(_bundle())
    legacy_id = _id("course-of-action", 5)
    payload["objects"].append({
        "type": "course-of-action",
        "id": legacy_id,
        "name": "Legacy PowerShell Mitigation",
        "description": "",
        "x_mitre_deprecated": True,
        "external_references": [{
            "source_name": "mitre-attack",
            "external_id": "T1059",
        }],
    })
    snapshot = _snapshot(json.dumps(payload, sort_keys=True).encode())
    legacy = snapshot.by_stix_id[legacy_id]
    assert type(legacy) is AttackMitigation
    assert legacy.attack_id == "T1059"
    assert legacy.deprecated is True
    assert type(snapshot.by_attack_id["T1059"]) is AttackTechnique

    payload["objects"][-1]["x_mitre_deprecated"] = False
    with pytest.raises(ValueError, match="attack_mitigation_id_invalid"):
        _snapshot(json.dumps(payload, sort_keys=True).encode())


def test_repository_digest_is_stable_under_platform_list_reordering() -> None:
    first = json.loads(_bundle())
    second = json.loads(_bundle())
    for item in first["objects"]:
        if item.get("type") == "attack-pattern":
            item["x_mitre_platforms"] = ["Windows", "Linux"]
    for item in second["objects"]:
        if item.get("type") == "attack-pattern":
            item["x_mitre_platforms"] = ["Linux", "Windows"]
    first_snapshot = _snapshot(json.dumps(first, sort_keys=True).encode())
    second_snapshot = _snapshot(json.dumps(second, sort_keys=True).encode())
    assert first_snapshot.digest == second_snapshot.digest
    assert first_snapshot.techniques[0].platforms == ("Linux", "Windows")
    with pytest.raises(ValueError, match="platforms_invalid"):
        replace(first_snapshot.techniques[0], platforms=("Windows", "Linux"))


def test_repository_rejects_orphan_subtechnique_and_duplicate_json_keys() -> None:
    with pytest.raises(ValueError, match="parent_technique_missing"):
        _snapshot(_bundle(orphan=True))
    duplicate = b'{"type":"bundle","type":"bundle","id":"bundle--00000004-0000-4000-8000-000000000004","objects":[]}'
    with pytest.raises(ValueError, match="duplicate_json_key"):
        _snapshot(duplicate)


def test_repository_snapshot_rejects_hookable_forged_index_without_calling_hooks() -> None:
    snapshot = _snapshot()
    _TrapDict.called = False
    with pytest.raises(TypeError, match="attack_repository_attack_index_invalid"):
        replace(snapshot, by_attack_id=_TrapDict(snapshot.by_attack_id))
    assert _TrapDict.called is False


def test_repository_ready_no_match_is_ready_zero_not_unavailable(tmp_path: Path) -> None:
    lock_set = ResourceLockSet()
    lock_set.acquire(tmp_path / "mitre-runtime.lock", writable=True)
    configure_mitre_runtime(
        _snapshot(), enabled=True, status={"unavailable_reason": ""}, lock_set=lock_set,
    )
    tags = normalize_tag_evidence(())
    chain = ChainEvidence("empty", "empty")
    probability, reason, evidence = mitre_probability_component(current_attack_mapping_fixture(tags, chain))
    assert probability == 0.0
    assert reason is None
    assert evidence["ready"] is True
    assert evidence["technique_ids_claimed"] is False
    release_mitre_runtime()


def test_repository_publication_contains_integrity_lock_and_config_provenance(tmp_path: Path) -> None:
    payload = _bundle()
    identity = git_blob_sha1_bytes(payload)
    root = tmp_path / "Mitre"
    root.mkdir()
    (root / f"enterprise-attack-v{identity}.json").write_bytes(payload)
    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}):
        runtime = initialize_mitre_from_args(SimpleNamespace(
            no_mitre=False, mitre_config=None, mitre_force_refresh=False,
            mitre_no_download=True, mitre_api_url=None, mitre_ref=None,
        ))
        evidence = official_attack_probability_evidence(current_attack_mapping_fixture(normalize_tag_evidence(()), ChainEvidence("e", "e")))
        status = evidence["repository_status"]
        assert runtime.available is True
        assert status["integrity_state"] == "semantic_and_local_integrity_valid"
        assert status["lock_state"] == "active_files_locked"
        assert status["config_state"] == "typed_defaults"
        with pytest.raises(TypeError):
            runtime.status["object_counts"]["attack-pattern"] = 0
        release_mitre_runtime()


def test_attack_config_rejects_other_api_paths_and_unsafe_refs() -> None:
    with pytest.raises(ValueError, match="api_identity_rejected"):
        AttackConfig(api_url="https://api.github.com/repos/other/project/contents/enterprise-attack.json")
    for ref in ("../main", "main..backup", "main/"):
        with pytest.raises(ValueError, match="ref_invalid"):
            AttackConfig(ref=ref)


def test_download_url_must_match_configured_repository_and_ref(tmp_path: Path) -> None:
    payload = _bundle()
    identity = json.dumps({
        "name": "enterprise-attack.json", "sha": git_blob_sha1_bytes(payload),
        "download_url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/other/enterprise-attack/enterprise-attack.json",
    }).encode()
    with pytest.raises(ValueError, match="download_identity_rejected"):
        refresh_repository(tmp_path, AttackConfig(allow_download=True), opener=lambda *_a, **_k: _Response(identity))


def test_ambiguous_unindexed_local_caches_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "Mitre"
    root.mkdir()
    for label in ("A", "B"):
        payload = _bundle(label=label)
        (root / f"enterprise-attack-v{git_blob_sha1_bytes(payload)}.json").write_bytes(payload)
    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}):
        runtime = initialize_mitre_from_args(SimpleNamespace(
            no_mitre=False, mitre_config=None, mitre_force_refresh=False,
            mitre_no_download=True, mitre_api_url=None, mitre_ref=None,
        ))
        assert runtime.available is False
        assert runtime.status["unavailable_reason"] == "mitre_repository_unavailable"
        release_mitre_runtime()


def test_rejected_external_config_path_releases_sentinel_lock(tmp_path: Path) -> None:
    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}):
        runtime = initialize_mitre_from_args(SimpleNamespace(
            no_mitre=False, mitre_config=str(tmp_path / "outside.toml"),
            mitre_force_refresh=False, mitre_no_download=True,
            mitre_api_url=None, mitre_ref=None,
        ))
        assert runtime.available is False
        assert runtime.status["unavailable_reason"] == "mitre_initialization_failed"
        locks = ResourceLockSet()
        locks.acquire(tmp_path / "Mitre" / ".umige-mitre.lock", writable=True)
        locks.release_all()
        release_mitre_runtime()
