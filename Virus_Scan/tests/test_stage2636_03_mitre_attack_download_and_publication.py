from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.attack.config import AttackConfig, config_toml
from Virus_Scan.detection.attack.download import (
    activate_packaged_seed_repository, refresh_repository,
)
from Virus_Scan.detection.attack.integrity import (
    git_blob_sha1_bytes, sha256_bytes,
)
from Virus_Scan.detection.attack.packaged_seed import (
    PACKAGED_ATTACK_SEED_GIT_BLOB_SHA1, PACKAGED_ATTACK_SEED_SHA256,
)
from Virus_Scan.detection.scoring.adaptive.evidence_projection_components import mitre_probability_component
from Virus_Scan.detection.scoring.adaptive.evidence_projection import build_probability_features
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.orchestration import mitre_initialization
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import current_attack_mapping_fixture
from Virus_Scan.runtime.api import release_mitre_runtime


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


def _bundle() -> bytes:
    return json.dumps({
        "type": "bundle",
        "id": "bundle--00000001-0000-4000-8000-000000000001",
        "objects": [
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--00000002-0000-4000-8000-000000000002",
                "name": "Credential Access", "description": "",
                "x_mitre_shortname": "credential-access",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0006"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--00000003-0000-4000-8000-000000000003",
                "name": "OS Credential Dumping", "description": "",
                "x_mitre_platforms": ["Windows"],
                "kill_chain_phases": [{"phase_name": "credential-access"}],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1003"}],
            },
        ],
    }, sort_keys=True).encode()




def test_packaged_offline_seed_is_atomically_activated_from_repository_owned_identity(
    tmp_path: Path,
) -> None:
    repository_root = Path(__file__).resolve().parents[2]
    payload = (repository_root / "Mitre/enterprise-attack.json").read_bytes()
    root = tmp_path / "Mitre"
    root.mkdir()
    seed = root / "enterprise-attack.json"
    seed.write_bytes(payload)

    snapshot, state, active = activate_packaged_seed_repository(
        root, seed, maximum_bytes=AttackConfig().maximum_bytes,
    )

    assert active.name == f"enterprise-attack-v{PACKAGED_ATTACK_SEED_GIT_BLOB_SHA1}.json"
    assert snapshot.version.dataset_version == PACKAGED_ATTACK_SEED_GIT_BLOB_SHA1
    assert state["local_sha256"] == PACKAGED_ATTACK_SEED_SHA256
    assert state["activation_state"] == "seed_validated"
    assert (root / "mitre_state.json").is_file()
    assert (root / "enterprise-attack-index.json").is_file()


def test_pristine_start_uses_packaged_seed_without_reading_editable_config(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[2]
    root = tmp_path / "Mitre"
    root.mkdir()
    (root / "enterprise-attack.json").write_bytes(
        (repository_root / "Mitre/enterprise-attack.json").read_bytes()
    )
    # If normal startup read this editable file, initialization would fail.
    (root / "mitre_config.toml").write_text("invalid = [", encoding="utf-8")
    args = SimpleNamespace(
        no_mitre=False, mitre_config=None, mitre_force_refresh=False,
        mitre_no_download=True, mitre_api_url=None, mitre_ref=None, scheduler="serial",
    )

    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}):
        runtime = mitre_initialization.initialize_mitre_from_args(args)
        try:
            assert runtime.available is True
            assert runtime.status["config_state"] == "typed_defaults"
            assert runtime.status["refresh_state"] == "seed_activated"
            assert runtime.status["active_cache_source"] == "validated_offline_seed"
            assert runtime.status["sha1_verification_state"] == "packaged_seed_identity_verified"
            assert "api_identity_url" not in runtime.status
        finally:
            release_mitre_runtime()


def test_packaged_seed_digest_mismatch_fails_before_cache_activation(tmp_path: Path) -> None:
    root = tmp_path / "Mitre"
    root.mkdir()
    seed = root / "enterprise-attack.json"
    seed.write_bytes(_bundle())

    with pytest.raises(ValueError, match="attack_seed_sha256_mismatch"):
        activate_packaged_seed_repository(
            root, seed, maximum_bytes=AttackConfig().maximum_bytes,
        )

    assert not tuple(root.glob("enterprise-attack-v*.json"))
    assert not (root / "mitre_state.json").exists()
    assert not (root / "enterprise-attack-index.json").exists()


def test_contents_api_identity_download_and_atomic_promotion(tmp_path: Path) -> None:
    bundle = _bundle()
    expected = git_blob_sha1_bytes(bundle)
    identity = json.dumps({
        "name": "enterprise-attack.json", "sha": expected,
        "download_url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    }).encode()
    calls: list[str] = []

    def opener(request, timeout=0):
        calls.append(request.full_url)
        return _Response(identity if len(calls) == 1 else bundle)

    snapshot, state, bundle_path = refresh_repository(tmp_path, AttackConfig(allow_download=True), opener=opener)
    assert snapshot.version.expected_git_blob_sha1 == expected
    assert state["expected_git_blob_sha1"] == expected
    assert bundle_path.name == f"enterprise-attack-v{expected}.json"
    assert bundle_path.read_bytes() == bundle
    assert not tuple(tmp_path.glob("*.tmp"))
    assert (tmp_path / "mitre_state.json").is_file()


def test_api_sha_mismatch_rejects_without_promoting(tmp_path: Path) -> None:
    bundle = _bundle()
    identity = json.dumps({
        "name": "enterprise-attack.json", "sha": "0" * 40,
        "download_url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    }).encode()
    responses = iter((_Response(identity), _Response(bundle)))
    with pytest.raises(ValueError, match="sha1_mismatch"):
        refresh_repository(tmp_path, AttackConfig(allow_download=True), opener=lambda *_a, **_k: next(responses))
    assert not tuple(tmp_path.glob("enterprise-attack-v*.json"))
    assert not tuple(tmp_path.glob("*.tmp"))


def test_304_or_refresh_failure_retains_semantically_valid_local_cache(tmp_path: Path) -> None:
    bundle = _bundle()
    expected = git_blob_sha1_bytes(bundle)
    root = tmp_path / "Mitre"
    root.mkdir()
    (root / f"enterprise-attack-v{expected}.json").write_bytes(bundle)
    def fail_refresh(*_args, **_kwargs):
        raise HTTPError("https://api.github.com", 304, "Not Modified", {}, None)

    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}), patch.object(
        mitre_initialization, "refresh_repository", fail_refresh,
    ):
        state = mitre_initialization.initialize_mitre_from_args(SimpleNamespace(
            no_mitre=False, mitre_config=None, mitre_force_refresh=True,
            mitre_no_download=False, mitre_api_url=None, mitre_ref=None,
        ))
        assert state.available is True
        assert state.status["refresh_failure"] == "last_known_good_retained"
        assert state.status["sha1_verification_state"] == "local_git_blob_recomputed"
        release_mitre_runtime()


def test_probability_publication_keeps_attack_chain_and_mitre_independent() -> None:
    tags = normalize_tag_evidence(("credential_access",))
    chain = ChainEvidence("v", "d")
    release_mitre_runtime()
    probability, reason, evidence = mitre_probability_component(current_attack_mapping_fixture(tags, chain))
    assert probability == 0.0
    assert reason == "mitre_official_mapping_unavailable"
    assert evidence["unavailable_reason"] == "mitre_runtime_released"
    assert evidence["technique_ids_claimed"] is False
    source = Path("Virus_Scan/detection/scoring/adaptive/evidence_projection.py").read_text()
    assert "p_attack_intelligence" in source
    assert "p_chain" in source
    assert "p_mitre" in source
    assert "mitre_evidence_json" in source
