"""Stage2636.10014 process fast-path ATT&CK boundary regressions."""
from __future__ import annotations

import json
from pathlib import Path

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.detection.attack.api import (
    official_attack_fast_path_policy,
    serialize_official_attack_probability_evidence,
)
from Virus_Scan.detection.attack.integrity import git_blob_sha1_bytes, sha256_bytes
from Virus_Scan.detection.attack.stix_importer import import_stix_bundle
from Virus_Scan.detection.enrichment.prefilter.scan import strict_fast_prefilter
from Virus_Scan.detection.scoring.prefilter.fast_benign_bypass import (
    extremely_strict_fast_benign_bypass_after_prefilter,
)
from Virus_Scan.orchestration.mitre_initialization import initialize_mitre_worker_runtime
from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.scheduler.workers.inmemory_worker_bootstrap_steps import configure_worker_mitre_runtime
from Virus_Scan.runtime.api import (
    ResourceLockSet,
    configure_mitre_runtime,
    release_mitre_runtime,
)


def _id(kind: str, number: int) -> str:
    return f"{kind}--{number:08x}-0000-4000-8000-{number:012x}"


def _snapshot_payload() -> bytes:
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
    payload = _snapshot_payload()
    identity = git_blob_sha1_bytes(payload)
    return import_stix_bundle(
        payload,
        dataset_version=identity,
        source_ref="test-ref",
        expected_git_blob_sha1=identity,
        computed_git_blob_sha1=identity,
        local_sha256=sha256_bytes(payload),
    )


def test_active_mitre_repository_forces_boring_text_through_full_pipeline(
    tmp_path: Path,
) -> None:
    target = tmp_path / "boring.txt"
    target.write_text("ordinary documentation line\n", encoding="utf-8")
    lock_set = ResourceLockSet()
    lock_set.acquire(tmp_path / "mitre-runtime.lock", writable=True)
    configure_mitre_runtime(
        _snapshot(),
        enabled=True,
        status={"unavailable_reason": ""},
        lock_set=lock_set,
    )
    try:
        prefilter = strict_fast_prefilter(str(target), compiled_rules=None, artifact_read_snapshot=artifact_read_snapshot_fixture(target))
        assert prefilter["fast_result"] is None
        assert prefilter["force_full"] is True
        assert prefilter["meta"]["mitre_full_pipeline_required"] is True
        assert extremely_strict_fast_benign_bypass_after_prefilter(
            str(target),
            tags=(),
            compiled_rules=None,
        ) is None
    finally:
        release_mitre_runtime()


def test_unavailable_mitre_fast_path_publishes_explicit_zero_authority(
    tmp_path: Path,
) -> None:
    release_mitre_runtime()
    target = tmp_path / "boring.txt"
    target.write_text("ordinary documentation line\n", encoding="utf-8")
    prefilter = strict_fast_prefilter(str(target), compiled_rules=None, artifact_read_snapshot=artifact_read_snapshot_fixture(target))
    fast_result = prefilter["fast_result"]
    assert type(fast_result) is dict
    compact = compact_result_record(fast_result)
    model_evidence = compact["model_evidence"]
    assert model_evidence["feature_probabilities"]["mitre"] == 0.0
    assert model_evidence["mitre_evidence"]["ready"] is False
    assert model_evidence["mitre_evidence"]["probability"] == 0.0
    assert model_evidence["mitre_evidence"]["technique_ids_claimed"] is False



def test_empty_official_attack_buckets_remain_empty_after_fast_result_detachment(
    tmp_path: Path,
) -> None:
    release_mitre_runtime()
    target = tmp_path / "empty-buckets.txt"
    target.write_text("ordinary documentation line\n", encoding="utf-8")
    fast_result = strict_fast_prefilter(str(target), compiled_rules=None, artifact_read_snapshot=artifact_read_snapshot_fixture(target))["fast_result"]
    assert type(fast_result) is dict
    raw_evidence = fast_result["model_evidence"]["mitre_evidence"]
    assert raw_evidence["confirmed"] == []
    assert raw_evidence["candidate"] == []
    assert raw_evidence["rejected"] == []
    evidence = compact_result_record(fast_result)["model_evidence"]["mitre_evidence"]
    assert evidence["confirmed"] == ()
    assert evidence["candidate"] == ()
    assert evidence["rejected"] == ()
    encoded = serialize_official_attack_probability_evidence(evidence)
    assert json.loads(encoded)["confirmed"] == []


def test_spawned_worker_loads_exact_parent_approved_repository(tmp_path: Path) -> None:
    release_mitre_runtime()
    root = tmp_path / "Mitre"
    root.mkdir()
    payload = _snapshot_payload()
    identity = git_blob_sha1_bytes(payload)
    bundle = root / f"enterprise-attack-v{identity}.json"
    bundle.write_bytes(payload)
    expected = _snapshot()
    runtime = initialize_mitre_worker_runtime(
        root=str(root),
        enabled=True,
        available=True,
        expected_repository_digest=expected.digest,
        expected_dataset_version=expected.version.dataset_version,
        unavailable_reason="",
    )
    try:
        assert runtime.available is True
        assert runtime.repository is not None
        assert runtime.repository.digest == expected.digest
        allowed, evidence = official_attack_fast_path_policy()
        assert allowed is False
        assert evidence == {}
    finally:
        release_mitre_runtime()


def test_worker_bootstrap_uses_one_explicit_mitre_initializer_descriptor() -> None:
    calls: list[dict[str, object]] = []

    def initializer(**kwargs: object) -> object:
        calls.append(dict(kwargs))
        return object()

    configure_worker_mitre_runtime({
        "mitre_initializer": initializer,
        "mitre_root": "/runtime/Mitre",
        "mitre_enabled": True,
        "mitre_available": True,
        "mitre_repository_digest": "a" * 64,
        "mitre_dataset_version": "b" * 40,
        "mitre_unavailable_reason": "",
    })
    assert calls == [{
        "root": "/runtime/Mitre",
        "enabled": True,
        "available": True,
        "expected_repository_digest": "a" * 64,
        "expected_dataset_version": "b" * 40,
        "unavailable_reason": "",
    }]
