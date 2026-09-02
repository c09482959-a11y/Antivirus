from __future__ import annotations

from argparse import Namespace
from contextlib import contextmanager
from io import BytesIO
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
import urllib.error
import zipfile

import pytest

from Virus_Scan.cli.args import parse_args
from Virus_Scan.orchestration.yara_initialization import initialize_yara_from_args
from Virus_Scan.runtime.api import (
    ResourceFileLock, ResourceLockSet, RuntimeContext, release_yara_runtime, yara_rules_state,
    yara_runtime_snapshot,
)
from Virus_Scan.tests.support.native_filesystem_alias import (
    create_native_directory_alias,
    create_native_file_alias,
)
from Virus_Scan.yara.config import YaraConfig, config_toml, load_config
from Virus_Scan.yara.control_files import ensure_generated_controls
from Virus_Scan.yara.download import acquire_official_archive
from Virus_Scan.yara.loader import load_yara_rules, resolve_rule_source
from Virus_Scan.yara.download_io import download_archive_temp, load_json_state, request_bytes, unique_temp
from Virus_Scan.yara.validation import RELEASE_API_URL, YARA_RELEASE_MANIFEST_NAME


class _Response:
    def __init__(self, payload: bytes, url: str, headers: dict[str, str] | None = None) -> None:
        self._payload = payload
        self._offset = 0
        self._headers = {} if headers is None else dict(headers)
        self._url = url

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self._payload) - self._offset
        start = self._offset
        self._offset = min(len(self._payload), start + size)
        return self._payload[start:self._offset]

    def getheader(self, name: str) -> str | None:
        return self._headers.get(name)

    def geturl(self) -> str:
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        return False


class _OfficialOpener:
    def __init__(self, release: bytes, checksum: bytes, archive: bytes, archive_modes: list[str] | None = None) -> None:
        self.release = release
        self.checksum = checksum
        self.archive = archive
        self.archive_modes = [] if archive_modes is None else list(archive_modes)
        self.archive_requests: list[dict[str, str]] = []

    def __call__(self, request, timeout: int):
        url = request.full_url
        headers = {name.lower(): value for name, value in request.header_items()}
        if url == RELEASE_API_URL:
            return _Response(self.release, url)
        if url.endswith("/" + YARA_RELEASE_MANIFEST_NAME):
            return _Response(self.checksum, url)
        if url.endswith(".zip"):
            self.archive_requests.append(headers)
            mode = self.archive_modes.pop(0) if self.archive_modes else "download"
            if mode == "304":
                raise urllib.error.HTTPError(url, 304, "not modified", None, None)
            if mode == "error":
                raise urllib.error.URLError("offline")
            return _Response(self.archive, url, {"ETag": '"archive-v1"', "Last-Modified": "Sun, 12 Jul 2026 00:00:00 GMT"})
        raise AssertionError("unexpected URL: " + url)


class _FragmentedResponse(_Response):
    def __init__(self, chunks: tuple[bytes, ...], url: str) -> None:
        super().__init__(b"", url)
        self._chunks = list(chunks) + [b""]

    def read(self, size: int = -1) -> bytes:
        return self._chunks.pop(0)


@contextmanager
def _scoped_program_root(root: Path):
    names = ("UMIGE_BASE_DIR", "UMIGE_EXE_DIR", "UMIGE_PROGRAM_DIR")
    previous = {name: os.environ.get(name) for name in names}
    try:
        os.environ["UMIGE_BASE_DIR"] = str(root)
        os.environ.pop("UMIGE_EXE_DIR", None)
        os.environ.pop("UMIGE_PROGRAM_DIR", None)
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _archive_bytes() -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("rules/one.yar", b"rule one { condition: true }")
        archive.writestr("NOTICE.txt", b"fixture")
    return stream.getvalue()


def _release_bytes(kind: str, archive_size: int) -> bytes:
    tag = "20260712"
    archive_name = "yara-forge-rules-" + kind + ".zip"
    base = "https://github.com/YARAHQ/yara-forge/releases/download/" + tag + "/"
    return json.dumps({
        "id": 700,
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "assets": [
            {"id": 701, "name": archive_name, "browser_download_url": base + archive_name, "size": archive_size, "state": "uploaded"},
            {"id": 702, "name": YARA_RELEASE_MANIFEST_NAME, "browser_download_url": base + YARA_RELEASE_MANIFEST_NAME, "size": 256, "state": "uploaded"},
            {"id": 703, "name": "yara-forge-log.txt", "browser_download_url": base + "yara-forge-log.txt", "size": 42, "state": "uploaded"},
        ],
    }, sort_keys=True).encode("utf-8")


def _fixture(kind: str = "extended") -> tuple[bytes, bytes, bytes]:
    archive = _archive_bytes()
    digest = hashlib.sha256(archive).hexdigest()
    digests = {"core": "1" * 64, "extended": "2" * 64, "full": "3" * 64}
    digests[kind] = digest
    checksum = (
        f"{digests['core']}  yara-forge-rules-core.zip\n"
        f"{digests['extended']}  yara-forge-rules-extended.zip\n"
        f"{digests['full']}  yara-forge-rules-full.zip\n"
    ).encode("ascii")
    return _release_bytes(kind, len(archive)), checksum, archive


def test_official_acquisition_promotes_only_manifest_verified_archive(tmp_path: Path) -> None:
    release, checksum, archive = _fixture()
    opener = _OfficialOpener(release, checksum, archive)
    result = acquire_official_archive(tmp_path, YaraConfig(), "extended", opener=opener)
    assert result.source == "github_release_api"
    assert result.freshness_state == "downloaded"
    assert result.api_identity_checked is True
    assert result.snapshot.local_path.read_bytes() == archive
    assert result.snapshot.computed_sha256 == hashlib.sha256(archive).hexdigest()
    assert tuple(item.name for item in result.snapshot.members) == ("rules/one.yar",)
    assert not tuple(tmp_path.glob("*.download.tmp"))


def test_304_revalidates_cached_archive_and_repairs_corruption(tmp_path: Path) -> None:
    release, checksum, archive = _fixture()
    acquire_official_archive(tmp_path, YaraConfig(), "extended", opener=_OfficialOpener(release, checksum, archive))
    unchanged = acquire_official_archive(
        tmp_path,
        YaraConfig(),
        "extended",
        opener=_OfficialOpener(release, checksum, archive, ["304"]),
    )
    assert unchanged.freshness_state == "not_modified_revalidated"
    unchanged.snapshot.local_path.write_bytes(b"corrupt")
    repair_opener = _OfficialOpener(release, checksum, archive, ["304", "download"])
    repaired = acquire_official_archive(tmp_path, YaraConfig(), "extended", opener=repair_opener)
    assert repaired.freshness_state == "downloaded"
    assert repaired.snapshot.local_path.read_bytes() == archive
    assert len(repair_opener.archive_requests) == 2
    assert "if-none-match" in repair_opener.archive_requests[0]
    assert "if-none-match" not in repair_opener.archive_requests[1]


def test_failed_refresh_retains_last_known_good_and_removes_temporary_file(tmp_path: Path) -> None:
    release, checksum, archive = _fixture()
    first = acquire_official_archive(tmp_path, YaraConfig(), "extended", opener=_OfficialOpener(release, checksum, archive))
    bad_archive = _archive_bytes() + b"changed"
    fallback = acquire_official_archive(
        tmp_path,
        YaraConfig(),
        "extended",
        force_refresh=True,
        opener=_OfficialOpener(release, checksum, bad_archive),
    )
    assert fallback.source == "offline_last_known_good_cache"
    assert fallback.freshness_state == "last_known_good_retained"
    assert fallback.snapshot.local_path == first.snapshot.local_path
    assert fallback.snapshot.local_path.read_bytes() == archive
    assert not tuple(tmp_path.glob("*.download.tmp"))


def test_unique_download_temporary_paths_do_not_collide(tmp_path: Path) -> None:
    first = unique_temp(tmp_path, "rules.zip", ".download.tmp")
    second = unique_temp(tmp_path, "rules.zip", ".download.tmp")
    try:
        assert first != second
        assert first.parent == second.parent == tmp_path
    finally:
        first.unlink()
        second.unlink()


def test_download_io_rejects_symlinked_yara_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "Yara"
    root = create_native_directory_alias(root, outside).path
    with pytest.raises(ValueError, match="yara_download_directory_invalid"):
        unique_temp(root, "rules.zip", ".download.tmp")
    with pytest.raises(ValueError, match="yara_download_directory_invalid"):
        acquire_official_archive(
            root, YaraConfig(), "extended",
            opener=_OfficialOpener(*_fixture()),
        )
    assert tuple(outside.iterdir()) == ()


def test_request_bytes_consumes_fragmented_response_to_eof() -> None:
    url = RELEASE_API_URL

    def opener(_request, timeout: int):
        assert timeout == 5
        return _FragmentedResponse((b'{"id":', b"700}"), url)

    payload, etag, modified = request_bytes(
        url, maximum=64, timeout=5, opener=opener, release_asset=False,
    )
    assert payload == b'{"id":700}'
    assert etag == ""
    assert modified == ""


def test_generated_controls_are_deterministic_and_preserve_user_edits(tmp_path: Path) -> None:
    paths = ensure_generated_controls(tmp_path)
    original_schema = paths["schema"].read_bytes()
    paths["config"].write_text("user-edited = true\n", encoding="utf-8")
    repeated = ensure_generated_controls(tmp_path)
    assert repeated == paths
    assert paths["config"].read_text(encoding="utf-8") == "user-edited = true\n"
    assert paths["schema"].read_bytes() == original_schema


def test_generated_controls_reject_symlinked_existing_control(tmp_path: Path) -> None:
    root = tmp_path / "Yara"
    root.mkdir()
    outside = tmp_path / "outside-control"
    outside.mkdir()
    sentinel = outside / "sentinel.toml"
    sentinel.write_text(config_toml(), encoding="utf-8")
    create_native_directory_alias(root / "yara_config.toml", outside)
    with pytest.raises(ValueError, match="yara_control_path_invalid"):
        ensure_generated_controls(root)
    assert sentinel.read_text(encoding="utf-8") == config_toml()


def test_load_config_rejects_symlinked_config(tmp_path: Path) -> None:
    outside = tmp_path / "outside.toml"
    outside.write_text(config_toml(), encoding="utf-8")
    link = create_native_file_alias(tmp_path / "yara_config.toml", outside).path
    with pytest.raises(ValueError, match="yara_config_file_invalid"):
        load_config(link)


def test_resource_file_lock_rejects_symlink_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.lock"
    outside.write_bytes(b"sentinel")
    link = create_native_file_alias(tmp_path / ".umige-yara.lock", outside).path
    lock = ResourceFileLock(link, writable=True)
    with pytest.raises((OSError, ValueError)):
        lock.acquire()
    assert lock.acquired is False
    assert outside.read_bytes() == b"sentinel"


def test_resource_file_lock_rejects_symlinked_parent_ancestor(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = create_native_directory_alias(tmp_path / "alias", outside).path
    target = alias / "nested" / ".umige-yara.lock"
    lock = ResourceFileLock(target, writable=True)

    with pytest.raises((OSError, ValueError)):
        lock.acquire()

    assert lock.acquired is False
    assert not (outside / "nested").exists()


def test_loader_rejects_foreign_config_and_non_boolean_policy(tmp_path: Path) -> None:
    class ForeignConfig:
        pass

    with pytest.raises(TypeError, match="yara_loader_config_owner_invalid"):
        load_yara_rules(config=ForeignConfig())
    with pytest.raises(TypeError, match="yara_loader_policy_invalid"):
        load_yara_rules(auto_download=1, config=YaraConfig())


def test_explicit_rule_source_rejects_symlink_alias(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yar"
    outside.write_text("rule Outside { condition: true }\n", encoding="utf-8")
    link = create_native_file_alias(tmp_path / "rules.yar", outside).path
    assert resolve_rule_source(
        "extended", explicit_path=str(link), auto_download=False,
        force_refresh=False, config=YaraConfig(),
    ) is None


def test_no_yara_short_circuits_before_resource_root_creation(tmp_path: Path) -> None:
    with _scoped_program_root(tmp_path):
        compiled, ok = initialize_yara_from_args(RuntimeContext(), Namespace(no_yara=True))
    assert compiled is None
    assert ok is False
    assert not (tmp_path / "Yara").exists()


def test_cli_uses_release_api_and_config_controls_not_direct_asset_urls() -> None:
    args = parse_args(["--dir", ".", "--yara-config", "Yara/yara_config.toml", "--yara-status"])
    assert args.yara_config == "Yara/yara_config.toml"
    assert args.yara_status is True
    assert not hasattr(args, "yara_release_api_url")
    with pytest.raises(SystemExit):
        parse_args(["--dir", ".", "--yara-url", "https://example.invalid/rules.zip"])


def test_manifest_mismatch_never_promotes_archive_or_state(tmp_path: Path) -> None:
    release, manifest, archive = _fixture()
    bad_manifest = manifest.replace(hashlib.sha256(archive).hexdigest().encode("ascii"), ("f" * 64).encode("ascii"))
    with pytest.raises(ValueError, match="yara_local_archive_state_unavailable"):
        acquire_official_archive(tmp_path, YaraConfig(), "extended", opener=_OfficialOpener(release, bad_manifest, archive))
    assert not tuple(tmp_path.glob("*.zip"))
    assert not tuple(tmp_path.glob("yara_*_state.json"))
    assert not tuple(tmp_path.glob("*.download.tmp"))


def test_manifest_identity_change_disables_archive_conditional_reuse(tmp_path: Path) -> None:
    release, manifest, archive = _fixture()
    acquire_official_archive(tmp_path, YaraConfig(), "extended", opener=_OfficialOpener(release, manifest, archive))
    replacement = _archive_bytes() + b"replacement"
    replacement_manifest = manifest.replace(
        hashlib.sha256(archive).hexdigest().encode("ascii"),
        hashlib.sha256(replacement).hexdigest().encode("ascii"),
    )
    opener = _OfficialOpener(release, replacement_manifest, replacement)
    result = acquire_official_archive(tmp_path, YaraConfig(), "extended", opener=opener)
    assert result.freshness_state == "downloaded"
    assert "if-none-match" not in opener.archive_requests[0]


def test_http_final_redirect_authority_is_fail_closed() -> None:
    initial = "https://github.com/YARAHQ/yara-forge/releases/download/20260712/" + YARA_RELEASE_MANIFEST_NAME

    def opener(request, timeout: int):
        return _Response(b"payload", "https://evil.example.invalid/payload")

    with pytest.raises(ValueError, match="yara_http_release_redirect_rejected"):
        request_bytes(initial, maximum=1024, timeout=5, opener=opener, release_asset=True)


def test_release_asset_redirect_requires_signed_github_asset_shape() -> None:
    initial = "https://github.com/YARAHQ/yara-forge/releases/download/20260712/" + YARA_RELEASE_MANIFEST_NAME

    def opener(request, timeout: int):
        return _Response(b"payload", "https://release-assets.githubusercontent.com/not-a-release-asset?x=1")

    with pytest.raises(ValueError, match="yara_http_release_redirect_rejected"):
        request_bytes(initial, maximum=1024, timeout=5, opener=opener, release_asset=True)


def test_http_request_rejects_invalid_bounds_and_authority_before_open() -> None:
    calls = 0

    def opener(request, timeout: int):
        nonlocal calls
        calls += 1
        raise AssertionError("network opener must not be called")

    with pytest.raises(ValueError, match="yara_http_request_bounds_invalid"):
        request_bytes(RELEASE_API_URL, maximum=0, timeout=5, opener=opener, release_asset=False)
    with pytest.raises(ValueError, match="yara_http_api_url_rejected"):
        request_bytes("https://github.com/api", maximum=1024, timeout=5, opener=opener, release_asset=False)
    with pytest.raises(ValueError, match="yara_http_release_url_rejected"):
        request_bytes("https://evil.example.invalid/a", maximum=1024, timeout=5, opener=opener, release_asset=True)
    assert calls == 0


def test_archive_download_rejects_invalid_bounds_and_authority_before_open(tmp_path: Path) -> None:
    calls = 0

    def opener(request, timeout: int):
        nonlocal calls
        calls += 1
        raise AssertionError("network opener must not be called")

    valid = "https://github.com/YARAHQ/yara-forge/releases/download/20260712/rules.zip"
    with pytest.raises(ValueError, match="yara_archive_download_bounds_invalid"):
        download_archive_temp(valid, tmp_path, "rules.zip", maximum=21, timeout=5, opener=opener, headers={})
    with pytest.raises(ValueError, match="yara_http_release_url_rejected"):
        download_archive_temp(
            "https://evil.example.invalid/rules.zip",
            tmp_path,
            "rules.zip",
            maximum=1024,
            timeout=5,
            opener=opener,
            headers={},
        )
    assert calls == 0


def test_state_sidecar_is_strict_and_never_supplies_expected_archive_digest(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"state_version":"a","state_version":"b"}', encoding="utf-8")
    assert load_json_state(duplicate) is None
    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"value":NaN}', encoding="utf-8")
    assert load_json_state(nonfinite) is None

    release, manifest, archive = _fixture()
    first = acquire_official_archive(tmp_path, YaraConfig(), "extended", opener=_OfficialOpener(release, manifest, archive))
    state_path = tmp_path / "yara_extended_state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["expected_sha256"] = "f" * 64
    state["archive_sha256"] = "e" * 64
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    reused = acquire_official_archive(
        tmp_path,
        YaraConfig(),
        "extended",
        opener=_OfficialOpener(release, manifest, archive, ["304"]),
    )
    assert reused.freshness_state == "not_modified_revalidated"
    assert reused.snapshot.expected_sha256 == hashlib.sha256(archive).hexdigest()
    assert reused.snapshot.local_path == first.snapshot.local_path


def test_explicit_content_addressed_official_archive_retains_verified_trust(tmp_path: Path) -> None:
    release, manifest, archive = _fixture()
    acquired = acquire_official_archive(
        tmp_path, YaraConfig(), "extended",
        opener=_OfficialOpener(release, manifest, archive),
    )
    source = resolve_rule_source(
        "extended", explicit_path=str(acquired.snapshot.local_path),
        auto_download=False, force_refresh=False, config=YaraConfig(),
    )
    assert source is not None
    assert source.trust_state == "official_verified"
    assert source.acquisition is not None
    assert source.archive_sha256 == hashlib.sha256(archive).hexdigest()


def test_yara_runtime_owns_initialization_and_active_file_locks(tmp_path: Path) -> None:
    rule_path = tmp_path / "Yara" / "rules.yar"
    rule_path.parent.mkdir(parents=True)
    rule_path.write_text("rule one { condition: true }\n", encoding="utf-8")
    with _scoped_program_root(tmp_path):
        compiled, ok = initialize_yara_from_args(
            RuntimeContext(),
            Namespace(
                no_yara=False, no_yaralight=True, scheduler="serial",
                yara=str(rule_path), yara_config=None, yara_force_refresh=False,
                yara_no_download=True, yaralight_no_download=True,
                yara_no_cache=True, yara_release_api_url=None,
            ),
        )
        assert compiled is None
        assert ok is False
        state = yara_rules_state()
        locked = {path.resolve() for path in state.lock_paths()}
        assert (rule_path.parent / ".umige-yara.lock").resolve() in locked
        assert rule_path.resolve() in locked
        assert (rule_path.parent / "yara_config.toml").resolve() in locked
        writer = ResourceLockSet()
        with pytest.raises((BlockingIOError, OSError)):
            writer.acquire(rule_path, writable=True)
        sentinel = rule_path.parent / ".umige-yara.lock"
        with pytest.raises((BlockingIOError, OSError)):
            writer.acquire(sentinel, writable=True)
        writer.release_all()
        release_yara_runtime()
        writer.acquire(rule_path, writable=True)
        writer.release_all()
        writer.acquire(sentinel, writable=True)
        writer.release_all()


def test_queue_child_uses_parent_resources_readonly_without_sentinel_ownership(tmp_path: Path) -> None:
    rule_path = tmp_path / "Yara" / "rules.yar"
    rule_path.parent.mkdir(parents=True)
    rule_path.write_text("rule one { condition: true }\n", encoding="utf-8")
    child_code = r"""
from argparse import Namespace
from Virus_Scan.orchestration.yara_initialization import initialize_yara_from_args
from Virus_Scan.runtime.api import RuntimeContext, release_yara_runtime, yara_rules_state
compiled, ok = initialize_yara_from_args(
    RuntimeContext(),
    Namespace(
        no_yara=False, no_yaralight=True, scheduler='queue-child',
        yara=r'RULE_PATH', yara_config=None, yara_force_refresh=False,
        yara_no_download=True, yaralight_no_download=True,
        yara_no_cache=True, yara_release_api_url=None,
    ),
)
state = yara_rules_state()
print(ok, state.readonly(), any(path.name == '.umige-yara.lock' for path in state.lock_paths()), len(state.lock_paths()))
release_yara_runtime()
""".replace("RULE_PATH", str(rule_path))
    with _scoped_program_root(tmp_path):
        initialize_yara_from_args(
            RuntimeContext(),
            Namespace(
                no_yara=False, no_yaralight=True, scheduler="serial",
                yara=str(rule_path), yara_config=None, yara_force_refresh=False,
                yara_no_download=True, yaralight_no_download=True,
                yara_no_cache=True, yara_release_api_url=None,
            ),
        )
        child = subprocess.run(
            [sys.executable, "-c", child_code],
            cwd=Path.cwd(), env=os.environ.copy(), capture_output=True, text=True,
            timeout=30, check=False,
        )
        try:
            assert child.returncode == 0, child.stderr
            fields = child.stdout.strip().split()
            assert fields[:3] == ["False", "True", "False"]
            assert int(fields[3]) >= 4
        finally:
            release_yara_runtime()


def test_enabled_queue_child_does_not_create_missing_yara_root(tmp_path: Path) -> None:
    with _scoped_program_root(tmp_path):
        compiled, ok = initialize_yara_from_args(
            RuntimeContext(),
            Namespace(
                no_yara=False, no_yaralight=True, scheduler="queue-child",
                yara=None, yara_config=None, yara_force_refresh=False,
                yara_no_download=True, yaralight_no_download=True,
                yara_no_cache=True, yara_release_api_url=None,
            ),
        )
    assert compiled is None
    assert ok is False
    assert not (tmp_path / "Yara").exists()


def test_runtime_publication_exposes_verified_official_integrity_and_lock_truth(tmp_path: Path) -> None:
    root = tmp_path / "Yara"
    root.mkdir()
    release, manifest, archive = _fixture()
    acquired = acquire_official_archive(
        root, YaraConfig(), "extended",
        opener=_OfficialOpener(release, manifest, archive),
    )
    with _scoped_program_root(tmp_path):
        compiled, ok = initialize_yara_from_args(
            RuntimeContext(),
            Namespace(
                no_yara=False, no_yaralight=True, scheduler="serial",
                yara=str(acquired.snapshot.local_path), yara_config=None,
                yara_force_refresh=False, yara_no_download=True,
                yaralight_no_download=True, yara_no_cache=False,
                yara_release_api_url=None, yara_status=False,
            ),
        )
        try:
            snapshot = yara_runtime_snapshot()
            status = snapshot.status
            primary = status["primary"]
            assert snapshot.enabled is True
            if compiled is None:
                assert ok is False
                assert snapshot.available is False
                assert status["lock_state"] == "initialization_resources_locked"
                assert primary["compilation_state"] == "dependency_unavailable"
                assert primary["unavailable_reason"].startswith("yara-python unavailable")
            else:
                assert ok is True
                assert snapshot.available is True
                assert status["lock_state"] == "active_files_locked"
                assert primary["compilation_state"] == "fully_compiled"
                assert primary["unavailable_reason"] == ""
            assert status["config_schema_version"] == "yara_config_v2"
            assert status["config_source"] == "typed_defaults"
            assert status["full_enabled"] is True
            assert status["light_enabled"] is False
            assert status["locked_resource_count"] >= 7
            assert primary["source_trust"] == "official_verified"
            assert primary["integrity_state"] == "official_manifest_sha256_verified"
            assert primary["release_id"] == 700
            assert primary["release_tag"] == "20260712"
            assert primary["manifest_asset_name"] == YARA_RELEASE_MANIFEST_NAME
            assert primary["manifest_url"].endswith("/" + YARA_RELEASE_MANIFEST_NAME)
            assert primary["acquisition_source"] == "offline_active_cache"
            assert primary["archive_sha256_expected"] == hashlib.sha256(archive).hexdigest()
            assert primary["archive_sha256_computed"] == hashlib.sha256(archive).hexdigest()
            assert primary["freshness_state"] == "local_revalidated"
            with pytest.raises(TypeError):
                status["lock_state"] = "mutated"
        finally:
            release_yara_runtime()


def test_yara_status_flag_logs_deterministic_publication(caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
    with _scoped_program_root(tmp_path), caplog.at_level("INFO"):
        initialize_yara_from_args(
            RuntimeContext(), Namespace(no_yara=True, yara_status=True),
        )
        try:
            records = [record.getMessage() for record in caplog.records if record.getMessage().startswith("YARA status ")]
            assert len(records) == 1
            payload = json.loads(records[0].removeprefix("YARA status "))
            assert payload["publication_version"] == "yara_publication_v1"
            assert payload["enabled"] is False
            assert payload["available"] is False
            assert payload["unavailable_reason"] == "yara_disabled"
        finally:
            release_yara_runtime()
