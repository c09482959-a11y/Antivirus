from __future__ import annotations
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import current_attack_mapping_fixture

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.no_hook_materialization import no_hook_materialize
from Virus_Scan.detection.attack.api import (
    official_attack_probability_evidence,
    serialize_official_attack_probability_evidence,
)
from Virus_Scan.detection.attack.integrity import git_blob_sha1_bytes, sha256_bytes
from Virus_Scan.detection.attack.publication import parse_official_attack_probability_evidence
from Virus_Scan.detection.attack.mapping.contracts import AttackMappingResult
from Virus_Scan.detection.attack.versioning import (
    ATTACK_EVALUATION_PROVENANCE,
    ATTACK_MAPPING_POLICY_VERSION,
)
from Virus_Scan.detection.api.attack_repository_status_contracts import (
    validate_published_repository_status,
)
from Virus_Scan.detection.attack.stix_importer import import_stix_bundle
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.orchestration.mitre_initialization import initialize_mitre_from_args
from Virus_Scan.runtime.api import (
    ResourceLockSet,
    configure_mitre_runtime,
    mitre_runtime_snapshot,
    release_mitre_runtime,
)


def _id(kind: str, number: int) -> str:
    return f"{kind}--{number:08x}-0000-4000-8000-{number:012x}"


def _bundle() -> bytes:
    return json.dumps(
        {
            "type": "bundle",
            "id": _id("bundle", 1),
            "objects": [
                {
                    "type": "x-mitre-tactic",
                    "id": _id("x-mitre-tactic", 2),
                    "name": "Execution",
                    "description": "",
                    "x_mitre_shortname": "execution",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "TA0002"},
                    ],
                },
                {
                    "type": "attack-pattern",
                    "id": _id("attack-pattern", 3),
                    "name": "Command and Scripting Interpreter",
                    "description": "",
                    "x_mitre_platforms": ["Windows"],
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
                    ],
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1059"},
                    ],
                },
            ],
        },
        sort_keys=True,
    ).encode()


def _snapshot():
    payload = _bundle()
    identity = git_blob_sha1_bytes(payload)
    return import_stix_bundle(
        payload,
        dataset_version=identity,
        source_ref="test-ref",
        expected_git_blob_sha1=identity,
        computed_git_blob_sha1=identity,
        local_sha256=sha256_bytes(payload),
    )


def _args() -> SimpleNamespace:
    return SimpleNamespace(
        no_mitre=False,
        mitre_config=None,
        mitre_force_refresh=False,
        mitre_no_download=True,
        mitre_api_url=None,
        mitre_ref=None,
    )


def _initialize_local(tmp_path: Path):
    payload = _bundle()
    identity = git_blob_sha1_bytes(payload)
    root = tmp_path / "Mitre"
    root.mkdir()
    bundle = root / f"enterprise-attack-v{identity}.json"
    bundle.write_bytes(payload)
    runtime = initialize_mitre_from_args(_args())
    return runtime, root, bundle


def test_runtime_status_identity_is_derived_from_repository_snapshot(tmp_path: Path) -> None:
    snapshot = _snapshot()
    lock_set = ResourceLockSet()
    lock_set.acquire(tmp_path / "mitre-runtime.lock", writable=True)
    with pytest.raises(ValueError, match="status_identity_mismatch"):
        configure_mitre_runtime(
            snapshot,
            enabled=True,
            status={
                "unavailable_reason": "",
                "expected_git_blob_sha1": "0" * 40,
            },
            lock_set=lock_set,
        )
    with pytest.raises(ValueError, match="status_identity_mismatch"):
        configure_mitre_runtime(
            snapshot,
            enabled=True,
            status={
                "unavailable_reason": "",
                "object_counts": {"attack-pattern": 999},
            },
            lock_set=lock_set,
        )
    with pytest.raises(TypeError, match="status_bool"):
        configure_mitre_runtime(
            snapshot,
            enabled=True,
            status={"unavailable_reason": "", "api_identity_checked": "yes"},
            lock_set=lock_set,
        )
    runtime = configure_mitre_runtime(
        snapshot,
        enabled=True,
        status={"unavailable_reason": ""},
        lock_set=lock_set,
    )
    assert runtime.status["dataset_version"] == snapshot.version.dataset_version
    assert runtime.status["object_counts"] == snapshot.object_counts
    assert runtime.status["source_ref"] == "test-ref"
    release_mitre_runtime()


def test_release_resets_disabled_runtime_to_neutral_released_state() -> None:
    configure_mitre_runtime(
        None,
        enabled=False,
        status={"unavailable_reason": "mitre_disabled"},
        lock_set=None,
    )
    release_mitre_runtime()
    runtime = mitre_runtime_snapshot()
    assert runtime.enabled is True
    assert runtime.available is False
    assert runtime.repository is None
    assert dict(runtime.status) == {
        "unavailable_reason": "mitre_runtime_released",
        "enabled": True,
        "available": False,
    }


def test_ready_repository_requires_live_runtime_lock_set() -> None:
    with pytest.raises(ValueError, match="repository_lock_required"):
        configure_mitre_runtime(
            _snapshot(), enabled=True, status={"unavailable_reason": ""}, lock_set=None,
        )



def test_available_repository_status_remains_valid_when_mapping_evaluation_is_unavailable(
    tmp_path: Path,
) -> None:
    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}):
        runtime, _root, _bundle_path = _initialize_local(tmp_path)
        unavailable = AttackMappingResult(
            repository_digest="",
            dataset_version="",
            decisions=(),
            probability=0.0,
            probability_unavailable_reason="",
            ready=False,
            unavailable_reason="mapping_evaluation_failed",
            policy_version=ATTACK_MAPPING_POLICY_VERSION,
            evaluation_provenance=ATTACK_EVALUATION_PROVENANCE,
        )
        published_status = no_hook_materialize(
            runtime.status, reason_prefix="test_attack_repository_status",
        )
        validated = validate_published_repository_status(
            published_status, unavailable,
        )
        assert validated["available"] is True
        assert validated["repository_digest"] == runtime.repository.digest
        assert validated["dataset_version"] == runtime.repository.version.dataset_version
        assert validated["unavailable_reason"] == ""
        release_mitre_runtime()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("api_identity_checked", "yes"),
        ("expected_git_blob_sha1", "garbage"),
        ("local_sha256", "bad"),
        ("locked_resource_count", -1),
        ("object_counts", {"attack-pattern": 999999}),
        ("schema_version", "legacy-schema"),
    ),
)
def test_publication_rejects_forged_repository_status(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}):
        runtime, _root, _bundle_path = _initialize_local(tmp_path)
        assert runtime.available is True
        evidence = official_attack_probability_evidence(
            current_attack_mapping_fixture(
                normalize_tag_evidence(()), ChainEvidence("empty", "empty")
            )
        )
        canonical = serialize_official_attack_probability_evidence(evidence)
        assert parse_official_attack_probability_evidence(canonical)["ready"] is True
        forged = json.loads(canonical)
        forged["repository_status"][field] = value
        with pytest.raises((TypeError, ValueError)):
            parse_official_attack_probability_evidence(json.dumps(forged))
        release_mitre_runtime()



@pytest.mark.parametrize(
    "api_identity_url",
    (
        "https://user@api.github.com/repos/mitre-attack/attack-stix-data/contents/enterprise-attack/enterprise-attack.json?ref=master",
        "https://api.github.com:444/repos/mitre-attack/attack-stix-data/contents/enterprise-attack/enterprise-attack.json?ref=master",
    ),
)
def test_publication_rejects_noncanonical_api_authority(
    tmp_path: Path, api_identity_url: str,
) -> None:
    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}):
        runtime, _root, _bundle_path = _initialize_local(tmp_path)
        evidence = official_attack_probability_evidence(
            current_attack_mapping_fixture(
                normalize_tag_evidence(()), ChainEvidence("empty", "empty")
            )
        )
        forged = evidence.copy()
        forged_status = dict(evidence["repository_status"])
        forged_status["active_cache_source"] = "github_contents_api"
        forged_status["api_identity_checked"] = True
        forged_status["api_identity_url"] = api_identity_url
        forged["repository_status"] = forged_status
        with pytest.raises(ValueError, match="api_identity_invalid"):
            parse_official_attack_probability_evidence(json.dumps(forged))
        release_mitre_runtime()

def test_publication_rejects_api_ref_mismatch_with_repository_source_ref(
    tmp_path: Path,
) -> None:
    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}):
        runtime, _root, _bundle_path = _initialize_local(tmp_path)
        evidence = official_attack_probability_evidence(
            current_attack_mapping_fixture(
                normalize_tag_evidence(()), ChainEvidence("empty", "empty")
            )
        )
        forged = evidence.copy()
        forged_status = dict(evidence["repository_status"])
        forged_status["active_cache_source"] = "github_contents_api"
        forged_status["api_identity_checked"] = True
        forged_status["api_identity_url"] = (
            "https://api.github.com/repos/mitre-attack/attack-stix-data/contents/"
            "enterprise-attack/enterprise-attack.json?ref=different-ref"
        )
        forged["repository_status"] = forged_status
        with pytest.raises(ValueError, match="api_source_ref_mismatch"):
            parse_official_attack_probability_evidence(json.dumps(forged))
        release_mitre_runtime()


def test_active_repository_files_are_kernel_locked_until_runtime_release(tmp_path: Path) -> None:
    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}):
        runtime, root, bundle = _initialize_local(tmp_path)
        assert runtime.available is True
        assert runtime.status["locked_resource_count"] >= 6
        for path in (root / "mitre_config.toml", root / "mitre_config.schema.json", bundle):
            contender = ResourceLockSet()
            with pytest.raises((BlockingIOError, OSError)):
                contender.acquire(path, writable=True)
            contender.release_all()
        release_mitre_runtime()
        for path in (root / "mitre_config.toml", bundle):
            contender = ResourceLockSet()
            contender.acquire(path, writable=True)
            contender.release_all()


def test_unavailable_publication_rejects_stale_repository_identity() -> None:
    release_mitre_runtime()
    evidence = official_attack_probability_evidence(
        current_attack_mapping_fixture(
            normalize_tag_evidence(()), ChainEvidence("empty", "empty")
        )
    )
    canonical = serialize_official_attack_probability_evidence(evidence)
    forged = json.loads(canonical)
    forged["repository_status"]["dataset_version"] = "a" * 40
    with pytest.raises(ValueError, match="unavailable_state"):
        parse_official_attack_probability_evidence(json.dumps(forged))
