"""Bounded GitHub Contents API refresh transaction for Enterprise ATT&CK."""
from __future__ import annotations

import json
import os
from pathlib import Path, PosixPath, WindowsPath
import tempfile
from types import MappingProxyType
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from Virus_Scan.runtime.api import (
    flush_open_writable_file,
    path_contains_filesystem_alias,
    stat_result_is_filesystem_alias,
)

_PATH_TYPES = (Path, PosixPath, WindowsPath)

from Virus_Scan.detection.attack.activation import build_attack_activation_record
from Virus_Scan.detection.attack.cache import atomic_write, write_state
from Virus_Scan.detection.attack.config import AttackConfig
from Virus_Scan.detection.attack.integrity import sha256_bytes, verify_git_blob_identity
from Virus_Scan.detection.attack.packaged_seed import (
    PACKAGED_ATTACK_SEED_GIT_BLOB_SHA1, PACKAGED_ATTACK_SEED_SHA256,
    PACKAGED_ATTACK_SEED_SOURCE_REF,
)
from Virus_Scan.detection.attack.stix_importer import import_stix_bundle
from Virus_Scan.detection.attack.validation import exact_https_endpoint

_API_HEADERS = MappingProxyType({
    "Accept": "application/vnd.github+json",
    "User-Agent": "UMIGE-Attack-Repository/1",
    "X-GitHub-Api-Version": "2022-11-28",
})
_RAW_REPOSITORY_PREFIX = "/mitre-attack/attack-stix-data/"
_RAW_REPOSITORY_SUFFIX = "/enterprise-attack/enterprise-attack.json"


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in out:
            raise ValueError("attack_contents_api_duplicate_key")
        out[str.__str__(key)] = value
    return out


def _reject_constant(_value: str) -> object:
    raise ValueError("attack_contents_api_nonfinite_value")


def _bounded_read(response: object, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(1024 * 1024, maximum + 1 - total))
        if not chunk:
            break
        if type(chunk) is not bytes:
            raise TypeError("attack_http_bytes_required")
        total += len(chunk)
        if total > maximum:
            raise ValueError("attack_http_payload_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def _download_to_temp(response: object, root: Path, maximum: int) -> Path:
    fd, temp_name = tempfile.mkstemp(prefix=".enterprise-attack.", suffix=".tmp", dir=root)
    temp = Path(temp_name)
    total = 0
    complete = False
    try:
        with os.fdopen(fd, "wb") as handle:
            while True:
                chunk = response.read(min(1024 * 1024, maximum + 1 - total))
                if not chunk:
                    break
                if type(chunk) is not bytes:
                    raise TypeError("attack_http_bytes_required")
                total += len(chunk)
                if total > maximum:
                    raise ValueError("attack_http_payload_too_large")
                handle.write(chunk)
            if total < 1:
                raise ValueError("attack_http_payload_empty")
            handle.flush()
            flush_open_writable_file(handle.fileno())
        complete = True
        return temp
    finally:
        if not complete and temp.exists():
            temp.unlink()


def _contents_identity(config: AttackConfig, *, opener=urlopen) -> tuple[str, str, str]:
    url = config.api_url + "?" + urlencode({"ref": config.ref})
    request = Request(url, headers=_API_HEADERS, method="GET")
    with opener(request, timeout=30) as response:
        data = _bounded_read(response, 1024 * 1024)
    payload = json.loads(
        data.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=_reject_constant,
    )
    if type(payload) is not dict:
        raise TypeError("attack_contents_api_mapping_required")
    expected = dict.get(payload, "sha")
    download_url = dict.get(payload, "download_url")
    name = dict.get(payload, "name")
    if type(expected) is not str or len(expected) != 40 or any(ch not in "0123456789abcdefABCDEF" for ch in expected):
        raise ValueError("attack_contents_api_sha_invalid")
    if name != "enterprise-attack.json" or type(download_url) is not str:
        raise ValueError("attack_contents_api_file_identity_invalid")
    expected_path = _RAW_REPOSITORY_PREFIX + config.ref + _RAW_REPOSITORY_SUFFIX
    download_url, _parsed = exact_https_endpoint(
        download_url, "attack_download_identity_rejected",
        hostname="raw.githubusercontent.com", path=expected_path,
    )
    return expected.lower(), download_url, url


def _activate_repository_payload(
    root: Path,
    data: bytes,
    *,
    expected_git_blob_sha1: str,
    source_ref: str,
    api_identity_url: str,
    activation_state: str,
):
    if type(root) not in _PATH_TYPES or type(data) is not bytes:
        raise TypeError("attack_activation_payload_contract_invalid")
    computed, local_sha256 = verify_git_blob_identity(
        data, expected_git_blob_sha1,
    )
    snapshot = import_stix_bundle(
        data, dataset_version=expected_git_blob_sha1, source_ref=source_ref,
        expected_git_blob_sha1=expected_git_blob_sha1,
        computed_git_blob_sha1=computed, local_sha256=local_sha256,
    )
    activation = build_attack_activation_record(snapshot)
    final_name = "enterprise-attack-v" + snapshot.version.dataset_version + ".json"
    final_path = root / final_name
    atomic_write(final_path, data)
    state = {
        "active_bundle": final_name,
        "dataset_version": snapshot.version.dataset_version,
        "repository_digest": snapshot.digest,
        "source_ref": source_ref,
        "expected_git_blob_sha1": expected_git_blob_sha1,
        "computed_git_blob_sha1": computed,
        "local_sha256": local_sha256,
        "object_counts": dict(snapshot.object_counts),
        "activation_state": activation_state,
        "activation_digest": activation.activation_digest,
        "activation_counts": activation.counts(),
    }
    if api_identity_url:
        state["api_identity_url"] = api_identity_url
    index_path = root / "enterprise-attack-index.json"
    state_path = root / "mitre_state.json"
    previous_index = index_path.read_bytes() if index_path.is_file() else None
    index_payload = (json.dumps(
        state, sort_keys=True, indent=2, allow_nan=False,
    ) + "\n").encode("utf-8")
    atomic_write(index_path, index_payload)
    try:
        write_state(state_path, state)
    except (OSError, TypeError, ValueError):
        if previous_index is None:
            if index_path.exists():
                index_path.unlink()
        else:
            atomic_write(index_path, previous_index)
        raise
    return snapshot, state, final_path


def _read_seed_bundle(path: Path, maximum: int) -> bytes:
    if type(path) not in _PATH_TYPES or type(maximum) is not int or type(maximum) is bool:
        raise TypeError("attack_seed_bundle_contract_invalid")
    initial = path.lstat()
    if (
        path_contains_filesystem_alias(path)
        or stat_result_is_filesystem_alias(initial)
        or not path.is_file()
        or not 1 <= initial.st_size <= maximum
    ):
        raise ValueError("attack_seed_bundle_file_invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino):
            raise ValueError("attack_seed_bundle_identity_changed")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(maximum + 1)
        if not 1 <= len(data) <= maximum:
            raise ValueError("attack_seed_bundle_size_invalid")
    finally:
        os.close(descriptor)
    final = path.lstat()
    if (
        path_contains_filesystem_alias(path)
        or stat_result_is_filesystem_alias(final)
        or (final.st_dev, final.st_ino) != (initial.st_dev, initial.st_ino)
    ):
        raise ValueError("attack_seed_bundle_identity_changed")
    return data


def activate_packaged_seed_repository(
    root: Path,
    seed_path: Path,
    *,
    maximum_bytes: int,
):
    """Activate the immutable packaged seed using repository-owned integrity identity."""
    if type(root) not in _PATH_TYPES or type(seed_path) not in _PATH_TYPES:
        raise TypeError("attack_seed_activation_contract_invalid")
    if type(maximum_bytes) is not int or type(maximum_bytes) is bool:
        raise TypeError("attack_seed_bundle_contract_invalid")
    resolved_root = root.resolve(strict=False)
    resolved_seed = seed_path.resolve(strict=False)
    if resolved_seed.parent != resolved_root:
        raise ValueError("attack_seed_path_outside_resource_root")
    data = _read_seed_bundle(resolved_seed, maximum_bytes)
    if sha256_bytes(data) != PACKAGED_ATTACK_SEED_SHA256:
        raise ValueError("attack_seed_sha256_mismatch")
    return _activate_repository_payload(
        resolved_root, data,
        expected_git_blob_sha1=PACKAGED_ATTACK_SEED_GIT_BLOB_SHA1,
        source_ref=PACKAGED_ATTACK_SEED_SOURCE_REF,
        api_identity_url="",
        activation_state="seed_validated",
    )


def refresh_repository(
    root: Path,
    config: AttackConfig,
    *,
    opener=urlopen,
):
    if type(root) not in _PATH_TYPES or type(config) is not AttackConfig:
        raise TypeError("attack_refresh_contract_invalid")
    root.mkdir(parents=True, exist_ok=True)
    expected, download_url, api_identity_url = _contents_identity(config, opener=opener)
    request = Request(download_url, headers={"User-Agent": _API_HEADERS["User-Agent"]}, method="GET")
    temp: Path | None = None
    try:
        with opener(request, timeout=60) as response:
            temp = _download_to_temp(response, root, config.maximum_bytes)
        data = temp.read_bytes()
        activated = _activate_repository_payload(
            root, data,
            expected_git_blob_sha1=expected,
            source_ref=config.ref,
            api_identity_url=api_identity_url,
            activation_state="candidate_validated",
        )
        temp.unlink()
        temp = None
        return activated
    finally:
        if temp is not None and temp.exists():
            temp.unlink()


__all__ = ("activate_packaged_seed_repository", "refresh_repository")
