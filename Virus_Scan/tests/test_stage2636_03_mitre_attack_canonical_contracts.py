from __future__ import annotations

from Virus_Scan.tests.support.attack_mapping_contract_fixtures import attack_mapping_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import current_attack_mapping_fixture

from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.attack.api import official_attack_probability_evidence
from Virus_Scan.detection.attack.cache import ensure_generated_controls
from Virus_Scan.detection.attack.config import config_readme, config_schema_json, config_toml
from Virus_Scan.detection.attack.integrity import git_blob_sha1_bytes, sha256_bytes, verify_git_blob_identity
from Virus_Scan.detection.attack.mapping.mapper import map_attack_evidence
from Virus_Scan.detection.attack.stix_importer import import_stix_bundle
from Virus_Scan.detection.attack.validation import official_attack_id, stix_id
from Virus_Scan.detection.scoring.adaptive.evidence_projection_components import mitre_probability_component
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.orchestration.mitre_initialization import initialize_mitre_from_args
from Virus_Scan.runtime.api import (
    ResourceLockSet, configure_mitre_runtime, release_mitre_runtime,
)


def _stix_id(kind: str, index: int) -> str:
    return f"{kind}--{index:08x}-0000-4000-8000-{index:012x}"


def _bundle(*, revoked_t1003: bool = False, conflicting: bool = False) -> bytes:
    tactic_defs = (
        ("TA0002", "Execution", "execution"),
        ("TA0005", "Defense Evasion", "defense-evasion"),
        ("TA0006", "Credential Access", "credential-access"),
        ("TA0008", "Lateral Movement", "lateral-movement"),
        ("TA0010", "Exfiltration", "exfiltration"),
        ("TA0011", "Command and Control", "command-and-control"),
    )
    technique_defs = (
        ("T1003", "OS Credential Dumping", "credential-access"),
        ("T1021", "Remote Services", "lateral-movement"),
        ("T1041", "Exfiltration Over C2 Channel", "exfiltration"),
        ("T1055", "Process Injection", "defense-evasion"),
        ("T1059", "Command and Scripting Interpreter", "execution"),
        ("T1059.001", "PowerShell", "execution"),
        ("T1105", "Ingress Tool Transfer", "command-and-control"),
        ("T1562", "Impair Defenses", "defense-evasion"),
        ("T1562.001", "Disable or Modify Tools", "defense-evasion"),
    )
    objects: list[dict[str, object]] = []
    for index, (attack_id, name, short) in enumerate(tactic_defs, 1):
        objects.append({
            "type": "x-mitre-tactic", "id": _stix_id("x-mitre-tactic", index),
            "name": name, "description": "", "x_mitre_shortname": short,
            "external_references": [{"source_name": "mitre-attack", "external_id": attack_id}],
        })
    for index, (attack_id, name, short) in enumerate(technique_defs, 101):
        objects.append({
            "type": "attack-pattern", "id": _stix_id("attack-pattern", index),
            "name": name, "description": "", "x_mitre_platforms": ["Windows"],
            "revoked": revoked_t1003 and attack_id == "T1003",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": short}],
            "external_references": [{"source_name": "mitre-attack", "external_id": attack_id}],
        })
    if conflicting:
        duplicate = dict(objects[-1])
        duplicate["id"] = _stix_id("attack-pattern", 999)
        duplicate["name"] = "Conflicting identity"
        objects.append(duplicate)
    return json.dumps({
        "type": "bundle", "id": _stix_id("bundle", 1000), "objects": objects,
    }, sort_keys=True).encode()


def _snapshot(data: bytes | None = None):
    payload = _bundle() if data is None else data
    git_sha = git_blob_sha1_bytes(payload)
    return import_stix_bundle(
        payload, dataset_version=git_sha, source_ref="test-ref",
        expected_git_blob_sha1=git_sha, computed_git_blob_sha1=git_sha,
        local_sha256=sha256_bytes(payload),
    )


def test_official_attack_and_stix_identity_validation() -> None:
    assert official_attack_id("T1059.001") == "T1059.001"
    assert stix_id(_stix_id("attack-pattern", 1)).startswith("attack-pattern--")
    for value in ("T12", "T1059.1", "CUSTOM", object()):
        with pytest.raises((TypeError, ValueError)):
            official_attack_id(value)
    with pytest.raises(ValueError):
        stix_id("attack-pattern--not-a-uuid")


def test_stix_importer_rejects_conflicting_official_identity() -> None:
    with pytest.raises(ValueError, match="duplicate_attack_identity"):
        _snapshot(_bundle(conflicting=True))


def test_git_blob_sha1_matches_known_git_fixture() -> None:
    assert git_blob_sha1_bytes(b"test content\n") == "d670460b4b4aece5915caf5c68d12f560a9fe3e4"
    computed, local = verify_git_blob_identity(b"test content\n", "d670460b4b4aece5915caf5c68d12f560a9fe3e4")
    assert computed == "d670460b4b4aece5915caf5c68d12f560a9fe3e4"
    assert len(local) == 64
    with pytest.raises(ValueError, match="mismatch"):
        verify_git_blob_identity(b"changed", "d670460b4b4aece5915caf5c68d12f560a9fe3e4")


def test_unbound_atomic_and_broad_reporting_tags_never_confirm() -> None:
    snapshot = _snapshot()
    chain = ChainEvidence("chain_registry_v1", "digest")
    broad = map_attack_evidence(
        snapshot, attack_mapping_evidence_fixture(physical_tag_evidence(("credential_access",)), chain),
    )
    atomic = map_attack_evidence(
        snapshot, attack_mapping_evidence_fixture(physical_tag_evidence(("lsass_access",)), chain),
    )
    for result in (broad, atomic):
        by_id = {decision.technique_id: decision for decision in result.decisions}
        assert by_id["T1003"].status == "rejected"
        assert by_id["T1003"].rejection_reason == "insufficient_implementation_evidence"
        assert result.probability == 0.0


def test_revoked_technique_never_scores() -> None:
    snapshot = _snapshot(_bundle(revoked_t1003=True))
    result = map_attack_evidence(snapshot, attack_mapping_evidence_fixture(physical_tag_evidence(("credential_access",)), ChainEvidence("v", "d")))
    record = {item.technique_id: item for item in result.decisions}["T1003"]
    assert record.status == "rejected"
    assert record.rejection_reason == "official_technique_revoked"
    assert result.probability == 0.0


def test_runtime_mapping_is_unavailable_without_repository_and_independent(tmp_path: Path) -> None:
    release_mitre_runtime()
    tags = physical_tag_evidence(("lsass_access",))
    chains = ChainEvidence("v", "d")
    probability, reason, evidence = mitre_probability_component(current_attack_mapping_fixture(tags, chains))
    assert probability == 0.0
    assert reason == "mitre_official_mapping_unavailable"
    assert evidence["unavailable_reason"] == "mitre_runtime_released"
    assert evidence["mapping_scope"] == "official_attack_techniques"
    lock_set = ResourceLockSet()
    lock_set.acquire(tmp_path / "mitre-runtime.lock", writable=True)
    configure_mitre_runtime(
        _snapshot(), enabled=True, status={"unavailable_reason": ""}, lock_set=lock_set,
    )
    probability, reason, evidence = mitre_probability_component(current_attack_mapping_fixture(tags, chains))
    assert probability == 0.0
    assert reason is None
    assert evidence["confirmed"] == ()
    release_mitre_runtime()


def test_generated_controls_are_deterministic_and_preserve_user_config(tmp_path: Path) -> None:
    first = ensure_generated_controls(tmp_path)
    assert first["config"].read_text() == config_toml()
    assert first["defaults"].read_text() == config_toml()
    assert first["schema"].read_text() == config_schema_json()
    assert first["readme"].read_text() == config_readme()
    first["config"].write_text("user-edited = true\n")
    ensure_generated_controls(tmp_path)
    assert first["config"].read_text() == "user-edited = true\n"


def test_explicit_mitre_config_is_the_only_file_activation_path(tmp_path: Path) -> None:
    payload = _bundle()
    git_sha = git_blob_sha1_bytes(payload)
    root = tmp_path / "Mitre"
    root.mkdir()
    (root / f"enterprise-attack-v{git_sha}.json").write_bytes(payload)
    config_path = root / "mitre_config.toml"
    config_path.write_text(config_toml(), encoding="utf-8")
    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}):
        snapshot = initialize_mitre_from_args(SimpleNamespace(
            no_mitre=False, mitre_config=str(config_path), mitre_force_refresh=False,
            mitre_no_download=True, mitre_api_url=None, mitre_ref=None,
        ))
        try:
            assert snapshot.available is True
            assert snapshot.status["config_state"] == "explicit_validated_toml"
        finally:
            release_mitre_runtime()


def test_invalid_explicit_mitre_config_fails_closed_without_typed_default_fallback(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Mitre"
    root.mkdir()
    config_path = root / "mitre_config.toml"
    config_path.write_text("enabled = true\n", encoding="utf-8")
    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}):
        snapshot = initialize_mitre_from_args(SimpleNamespace(
            no_mitre=False, mitre_config=str(config_path), mitre_force_refresh=False,
            mitre_no_download=True, mitre_api_url=None, mitre_ref=None,
        ))
        try:
            assert snapshot.available is False
            assert snapshot.status["unavailable_reason"] == "mitre_initialization_failed"
        finally:
            release_mitre_runtime()


def test_resource_lock_is_exclusive_and_crash_recoverable(tmp_path: Path) -> None:
    path = tmp_path / ".umige-mitre.lock"
    first = ResourceLockSet()
    first.acquire(path, writable=True)
    second = ResourceLockSet()
    with pytest.raises((BlockingIOError, OSError)):
        second.acquire(path, writable=True)
    first.release_all()
    second.acquire(path, writable=True)
    second.release_all()


def test_local_cache_initialization_never_needs_network(tmp_path: Path) -> None:
    payload = _bundle()
    git_sha = git_blob_sha1_bytes(payload)
    root = tmp_path / "Mitre"
    root.mkdir()
    (root / f"enterprise-attack-v{git_sha}.json").write_bytes(payload)
    (root / "mitre_config.toml").write_text("this is not valid toml = [", encoding="utf-8")
    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}):
        snapshot = initialize_mitre_from_args(SimpleNamespace(
            no_mitre=False, mitre_config=None, mitre_force_refresh=False,
            mitre_no_download=True, mitre_api_url=None, mitre_ref=None,
        ))
        assert snapshot.available is True
        assert snapshot.status["api_identity_checked"] is False
        assert snapshot.status["config_state"] == "typed_defaults"
        evidence = official_attack_probability_evidence(
            current_attack_mapping_fixture(
                physical_tag_evidence(("lsass_access",)), ChainEvidence("v", "d")
            )
        )
        assert evidence["probability"] == 0.0
        assert evidence["confirmed"] == ()
        release_mitre_runtime()


def test_public_source_has_no_legacy_mitre_owner_or_network_scan_path() -> None:
    root = Path("Virus_Scan")
    source = "\n".join(path.read_text() for path in (
        root / "detection" / "attack" / "api.py",
        root / "detection" / "attack" / "mapping" / "mapper.py",
        root / "detection" / "scoring" / "adaptive" / "evidence_projection_components.py",
    ))
    assert "mitre_mapping" not in source
    assert "MITRE_MAPPING_AVAILABLE" not in source
    assert "urlopen" not in source
    assert not (root / "detection" / "tags" / "heuristics" / "mitre_mapping.py").exists()
