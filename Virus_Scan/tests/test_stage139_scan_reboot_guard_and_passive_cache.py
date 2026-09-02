from pathlib import Path
import json
import os
from types import SimpleNamespace
import time


from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.core import cache
from Virus_Scan.tests.support.scan_cache_fixtures import disabled_scan_cache_identity
from Virus_Scan.runtime.scan_run_guard import acquire_parent_scan_guard, release_parent_scan_guard
from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle


def test_canonical_extension_normalizes_rpgm_encrypted_suffixes(tmp_path):
    assert get_scan_extension(tmp_path / 'Battle5.ogg_') == '.ogg'
    assert get_scan_extension(tmp_path / 'Actor1.png_') == '.png'


def test_passive_cache_lookup_reuses_canonical_artifact_digest(tmp_path):
    p = tmp_path / 'Battle5.ogg_'
    p.write_bytes(b'RPGMV' + b'\0' * 64)
    repository = scan_cache_repository()
    repository.configure(tmp_path / "profiles", enabled=True)
    try:
        snapshot = artifact_read_snapshot_fixture(p)
        result, sha = cache.pre_scan_cache_lookup(
            snapshot, execution_identity=disabled_scan_cache_identity(),
        )
        assert result is None
        assert sha == snapshot.content_sha256
    finally:
        repository.configure(tmp_path / "disabled", enabled=False)
        sqlite_lifecycle().close()

def test_parent_scan_guard_blocks_duplicate_and_releases(tmp_path):
    scan_root = tmp_path / 'Scan Logs'
    target = tmp_path / 'game'
    target.mkdir()
    args = SimpleNamespace(dir=str(target), scan_log_root=str(scan_root))
    acquire_parent_scan_guard(args, environ_get=lambda key, default=None: default)
    try:
        try:
            acquire_parent_scan_guard(args, environ_get=lambda key, default=None: default)
        except SystemExit as e:
            assert 'active UMIGE scan already running' in str(e)
        else:
            raise AssertionError('duplicate guard did not block')
    finally:
        release_parent_scan_guard()
    acquire_parent_scan_guard(args)
    release_parent_scan_guard()


def test_parent_scan_guard_ignored_for_queue_child(tmp_path):
    args = SimpleNamespace(dir=str(tmp_path), scan_log_root=str(tmp_path / 'Scan Logs'))
    assert acquire_parent_scan_guard(
        args,
        environ_get=lambda key, default=None: '1' if key == 'UMIGE_PROCESS_SHARD' else default,
    ) is None
