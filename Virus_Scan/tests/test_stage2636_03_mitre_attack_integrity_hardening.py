from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from Virus_Scan.detection.attack.cache import load_state
from Virus_Scan.detection.attack.config import AttackConfig, config_schema_json
from Virus_Scan.detection.attack.download import refresh_repository
from Virus_Scan.detection.attack.integrity import (
    git_blob_sha1_bytes,
    sha256_bytes,
    verify_git_blob_identity,
)
from Virus_Scan.detection.attack.stix_importer import import_stix_bundle
from Virus_Scan.detection.attack.versioning import ATTACK_CACHE_STATE_VERSION
from Virus_Scan.orchestration.mitre_initialization import initialize_mitre_from_args
from Virus_Scan.runtime.api import ResourceFileLock, ResourceLockSet, release_mitre_runtime
from Virus_Scan.scheduler.workers.spawn import ProcessQueueWorkerSpawnRequest, build_process_queue_worker_command


def _id(kind: str, number: int) -> str:
    return f"{kind}--{number:08x}-0000-4000-8000-{number:012x}"


def _bundle() -> bytes:
    objects = [
        {
            "type": "x-mitre-tactic",
            "id": _id("x-mitre-tactic", 1),
            "name": "Execution",
            "description": "",
            "x_mitre_shortname": "execution",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "TA0002"},
            ],
        },
        {
            "type": "attack-pattern",
            "id": _id("attack-pattern", 2),
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
    ]
    return json.dumps(
        {"type": "bundle", "id": _id("bundle", 3), "objects": objects},
        sort_keys=True,
    ).encode()


def _import(payload: bytes):
    identity = git_blob_sha1_bytes(payload)
    return import_stix_bundle(
        payload,
        dataset_version=identity,
        source_ref="test-ref",
        expected_git_blob_sha1=identity,
        computed_git_blob_sha1=identity,
        local_sha256=sha256_bytes(payload),
    )


class _Response:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size: int = -1) -> bytes:
        payload, self._payload = self._payload, b""
        return payload


def _args(*, no_download: bool = True, force_refresh: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        no_mitre=False,
        mitre_config=None,
        mitre_force_refresh=force_refresh,
        mitre_no_download=no_download,
        mitre_api_url=None,
        mitre_ref=None,
    )


def test_offline_bundle_identity_is_bound_to_activated_filename(tmp_path: Path) -> None:
    payload = _bundle()
    root = tmp_path / "Mitre"
    root.mkdir()
    false_identity = "0" * 40
    assert false_identity != git_blob_sha1_bytes(payload)
    (root / f"enterprise-attack-v{false_identity}.json").write_bytes(payload)
    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}):
        runtime = initialize_mitre_from_args(_args())
        assert runtime.available is False
        assert runtime.status["unavailable_reason"] == "mitre_repository_unavailable"
        release_mitre_runtime()


def test_no_download_and_force_refresh_conflict_without_network(tmp_path: Path) -> None:
    with patch.dict("os.environ", {"UMIGE_BASE_DIR": str(tmp_path)}), patch(
        "Virus_Scan.orchestration.mitre_initialization.refresh_repository",
        side_effect=AssertionError("network refresh must not run"),
    ) as refresh:
        runtime = initialize_mitre_from_args(_args(no_download=True, force_refresh=True))
        assert runtime.available is False
        assert runtime.status["unavailable_reason"] == "mitre_initialization_failed"
        refresh.assert_not_called()
        release_mitre_runtime()


def test_generated_schema_matches_exact_ref_contract() -> None:
    schema = json.loads(config_schema_json())
    ref_schema = schema["properties"]["ref"]
    assert ref_schema["maxLength"] == 128
    assert ref_schema["pattern"] == r"^(?!.*\.\.)(?!.*\/$)[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$"
    assert AttackConfig(ref="a" * 128).ref == "a" * 128
    for invalid in ("a" * 129, "../evil", "main/", "a..b", "-bad"):
        with pytest.raises(ValueError, match="ref_invalid"):
            AttackConfig(ref=invalid)



@pytest.mark.parametrize(
    "api_url",
    (
        "https://user@api.github.com/repos/mitre-attack/attack-stix-data/contents/enterprise-attack/enterprise-attack.json",
        "https://api.github.com:444/repos/mitre-attack/attack-stix-data/contents/enterprise-attack/enterprise-attack.json",
        "https://api.github.com/repos/mitre-attack/attack-stix-data/contents/enterprise-attack/enterprise-attack.json?ref=../evil",
    ),
)
def test_config_rejects_noncanonical_github_authority(api_url: str) -> None:
    with pytest.raises(ValueError, match="api_identity_rejected"):
        AttackConfig(api_url=api_url)


@pytest.mark.parametrize(
    "download_url",
    (
        "https://user@raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "https://raw.githubusercontent.com:444/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    ),
)
def test_contents_api_rejects_noncanonical_raw_authority(tmp_path: Path, download_url: str) -> None:
    payload = _bundle()
    identity = json.dumps({
        "name": "enterprise-attack.json",
        "sha": git_blob_sha1_bytes(payload),
        "download_url": download_url,
    }).encode()
    with pytest.raises(ValueError, match="download_identity_rejected"):
        refresh_repository(
            tmp_path, AttackConfig(allow_download=True),
            opener=lambda *_args, **_kwargs: _Response(identity),
        )

def test_contents_api_rejects_duplicate_identity_keys(tmp_path: Path) -> None:
    payload = _bundle()
    download_url = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/enterprise-attack/enterprise-attack.json"
    )
    identity = (
        '{"name":"enterprise-attack.json","sha":"'
        + git_blob_sha1_bytes(payload)
        + '","sha":"0000000000000000000000000000000000000000",'
        + '"download_url":"'
        + download_url
        + '"}'
    ).encode()
    with pytest.raises(ValueError, match="duplicate_key"):
        refresh_repository(
            tmp_path,
            AttackConfig(allow_download=True),
            opener=lambda *_args, **_kwargs: _Response(identity),
        )


def test_download_is_fsynced_to_unique_temp_before_identity_verification(tmp_path: Path) -> None:
    payload = _bundle()
    expected = git_blob_sha1_bytes(payload)
    identity = json.dumps(
        {
            "name": "enterprise-attack.json",
            "sha": expected,
            "download_url": (
                "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                "master/enterprise-attack/enterprise-attack.json"
            ),
        }
    ).encode()
    responses = iter((_Response(identity), _Response(payload)))

    def _verify(data: bytes, expected_identity: str) -> tuple[str, str]:
        temporary = tuple(tmp_path.glob(".enterprise-attack.*.tmp"))
        assert len(temporary) == 1
        assert temporary[0].read_bytes() == payload
        return verify_git_blob_identity(data, expected_identity)

    with patch(
        "Virus_Scan.detection.attack.download.verify_git_blob_identity",
        side_effect=_verify,
    ):
        snapshot, state, bundle_path = refresh_repository(
            tmp_path,
            AttackConfig(allow_download=True),
            opener=lambda *_args, **_kwargs: next(responses),
        )
    assert snapshot.version.dataset_version == expected
    assert state["expected_git_blob_sha1"] == expected
    assert bundle_path.name == f"enterprise-attack-v{expected}.json"
    assert not tuple(tmp_path.glob(".enterprise-attack.*.tmp"))


def test_state_loader_rejects_duplicate_keys(tmp_path: Path) -> None:
    state = tmp_path / "mitre_state.json"
    state.write_text(
        '{"state_version":"'
        + ATTACK_CACHE_STATE_VERSION
        + '","active_bundle":"first","active_bundle":"second"}',
        encoding="utf-8",
    )
    assert load_state(state) is None


def test_importer_rejects_duplicate_unsupported_object_identity() -> None:
    duplicate_id = _id("identity", 10)
    payload = json.dumps(
        {
            "type": "bundle",
            "id": _id("bundle", 11),
            "objects": [
                {"type": "identity", "id": duplicate_id},
                {"type": "identity", "id": duplicate_id},
            ],
        }
    ).encode()
    with pytest.raises(ValueError, match="duplicate_object_identity"):
        _import(payload)


def test_importer_rejects_stix_type_identity_mismatch() -> None:
    payload = json.dumps(
        {
            "type": "bundle",
            "id": _id("bundle", 12),
            "objects": [
                {"type": "identity", "id": _id("attack-pattern", 13)},
            ],
        }
    ).encode()
    with pytest.raises(ValueError, match="identity_type_mismatch"):
        _import(payload)


def test_resource_file_lock_rejects_double_acquire_and_recovers(tmp_path: Path) -> None:
    lock = ResourceFileLock(tmp_path / ".umige-mitre.lock", writable=True)
    lock.acquire()
    with pytest.raises(RuntimeError, match="already_acquired"):
        lock.acquire()
    assert lock.acquired is True
    lock.release()
    assert lock.acquired is False
    lock.acquire()
    lock.release()



def test_readonly_resource_locks_are_shared_and_deny_writers(tmp_path: Path) -> None:
    path = tmp_path / ("enterprise-attack-v" + "a" * 40 + ".json")
    path.write_bytes(b"fixture")
    first = ResourceLockSet()
    second = ResourceLockSet()
    writer = ResourceLockSet()
    first.acquire(path, writable=False)
    second.acquire(path, writable=False)
    with pytest.raises((BlockingIOError, OSError)):
        writer.acquire(path, writable=True)
    writer.release_all()
    second.release_all()
    first.release_all()


def test_queue_child_loads_parent_locked_repository_readonly(tmp_path: Path) -> None:
    payload = _bundle()
    identity = git_blob_sha1_bytes(payload)
    root = tmp_path / "Mitre"
    root.mkdir()
    (root / f"enterprise-attack-v{identity}.json").write_bytes(payload)
    parent_args = SimpleNamespace(
        no_mitre=False,
        mitre_config=None,
        mitre_force_refresh=False,
        mitre_no_download=True,
        mitre_api_url=None,
        mitre_ref=None,
        scheduler="serial",
    )
    child_code = """
from types import SimpleNamespace
from Virus_Scan.orchestration.mitre_initialization import initialize_mitre_from_args
from Virus_Scan.runtime.api import release_mitre_runtime
runtime = initialize_mitre_from_args(SimpleNamespace(
    no_mitre=False,
    mitre_config=None,
    mitre_force_refresh=False,
    mitre_no_download=True,
    mitre_api_url=None,
    mitre_ref=None,
    scheduler='queue-child',
))
print(runtime.available, runtime.status.get('config_state'), runtime.status.get('refresh_state'))
release_mitre_runtime()
"""
    with patch.dict(os.environ, {"UMIGE_BASE_DIR": str(tmp_path)}, clear=False):
        parent = initialize_mitre_from_args(parent_args)
        assert parent.available is True
        child = subprocess.run(
            [sys.executable, "-c", child_code],
            cwd=Path.cwd(),
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert child.returncode == 0
        assert child.stdout.strip() == "True parent_validated_readonly worker_readonly"
        release_mitre_runtime()


def test_process_queue_child_is_offline_and_propagates_parent_disable() -> None:
    request = ProcessQueueWorkerSpawnRequest(
        root="root",
        queue_dir="queue",
        output="out.json",
        worker_index=1,
        script_path=Path("scanner.py"),
        python_executable=sys.executable,
        env_base={"UMIGE_DEEP_SCAN_MODE": "auto"},
        progress_every=1,
        partial_output_every=0,
        slow_file_warn_sec=0.0,
        per_file_timeout_sec=0.0,
        throttle_sec=0.0,
        strict=False,
        scan_session_manifest_path=Path("scan_session_snapshot.json"),
    )
    with patch.dict(os.environ, {"UMIGE_NO_MITRE": "1"}, clear=False):
        command = build_process_queue_worker_command(request)
    assert "--mitre-no-download" in command
    assert "--no-mitre" in command


def test_disabled_parent_does_not_create_external_mitre_resources(tmp_path: Path) -> None:
    with patch.dict(os.environ, {"UMIGE_BASE_DIR": str(tmp_path)}, clear=False):
        state = initialize_mitre_from_args(SimpleNamespace(
            no_mitre=True, scheduler="serial", mitre_config=None,
            mitre_force_refresh=False, mitre_no_download=True,
            mitre_api_url=None, mitre_ref=None,
        ))
        try:
            assert state.enabled is False
            assert state.available is False
            assert dict(state.status)["unavailable_reason"] == "mitre_disabled"
            assert not (tmp_path / "Mitre").exists()
        finally:
            release_mitre_runtime()


def test_disabled_queue_child_does_not_create_external_mitre_resources(tmp_path: Path) -> None:
    with patch.dict(os.environ, {"UMIGE_BASE_DIR": str(tmp_path)}, clear=False):
        state = initialize_mitre_from_args(SimpleNamespace(
            no_mitre=True, scheduler="queue-child", mitre_config=None,
            mitre_force_refresh=False, mitre_no_download=True,
            mitre_api_url=None, mitre_ref=None,
        ))
        try:
            assert state.enabled is False
            assert state.available is False
            assert dict(state.status)["unavailable_reason"] == "mitre_disabled"
            assert not (tmp_path / "Mitre").exists()
        finally:
            release_mitre_runtime()
