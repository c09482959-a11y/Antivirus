"""Strict GitHub release-metadata admission for official YARA Forge assets."""
from __future__ import annotations

import json

from Virus_Scan.yara.contracts import YaraReleaseIdentity
from Virus_Scan.yara.validation import (
    YARA_RELEASE_MANIFEST_NAME, bounded_int, package_kind, release_asset_name,
    release_asset_url, release_tag,
)

_MAX_RELEASE_JSON_BYTES = 4 * 1024 * 1024
_MAX_MANIFEST_ASSET_BYTES = 1024 * 1024


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in out:
            raise ValueError("yara_release_json_duplicate_key")
        out[key] = value
    return out


def _release_json(data: bytes) -> dict[str, object]:
    if type(data) is not bytes:
        raise TypeError("yara_release_json_bytes_required")
    if not data or len(data) > _MAX_RELEASE_JSON_BYTES or b"\x00" in data:
        raise ValueError("yara_release_json_invalid")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("yara_release_json_invalid") from exc
    if type(value) is not dict:
        raise TypeError("yara_release_json_object_required")
    return value


def _asset_record(value: object, *, tag: str) -> tuple[int, str, str, int]:
    if type(value) is not dict:
        raise TypeError("yara_release_asset_record_invalid")
    asset_id = bounded_int(dict.get(value, "id"), "yara_release_asset_id_invalid", minimum=1, maximum=1 << 63)
    name = release_asset_name(dict.get(value, "name"))
    url = release_asset_url(dict.get(value, "browser_download_url"), tag=tag, name=name)
    size = bounded_int(dict.get(value, "size"), "yara_release_asset_size_invalid", minimum=1, maximum=1 << 31)
    state = dict.get(value, "state")
    if state != "uploaded":
        raise ValueError("yara_release_asset_state_invalid")
    return asset_id, name, url, size


def select_release_identity(data: bytes, package: str) -> YaraReleaseIdentity:
    record = _release_json(data)
    if dict.get(record, "draft") is not False or dict.get(record, "prerelease") is not False:
        raise ValueError("yara_release_state_rejected")
    release_id = bounded_int(dict.get(record, "id"), "yara_release_id_invalid", minimum=1, maximum=1 << 63)
    tag = release_tag(dict.get(record, "tag_name"))
    kind = package_kind(package)
    assets = dict.get(record, "assets")
    if type(assets) is not list or not assets or len(assets) > 128:
        raise TypeError("yara_release_assets_invalid")
    admitted = tuple(_asset_record(item, tag=tag) for item in assets)
    names = tuple(item[1] for item in admitted)
    ids = tuple(item[0] for item in admitted)
    if len(names) != len(set(names)) or len(ids) != len(set(ids)):
        raise ValueError("yara_release_assets_duplicate")
    archive_name = "yara-forge-rules-" + kind + ".zip"
    archive_matches = tuple(item for item in admitted if item[1] == archive_name)
    manifest_matches = tuple(item for item in admitted if item[1] == YARA_RELEASE_MANIFEST_NAME)
    if len(archive_matches) != 1:
        raise ValueError("yara_release_archive_asset_missing")
    if len(manifest_matches) != 1:
        raise ValueError("yara_release_manifest_asset_missing")
    archive = archive_matches[0]
    manifest = manifest_matches[0]
    if manifest[3] > _MAX_MANIFEST_ASSET_BYTES:
        raise ValueError("yara_release_manifest_asset_oversized")
    return YaraReleaseIdentity(
        release_id=release_id,
        release_tag=tag,
        package_kind=kind,
        archive_asset_id=archive[0],
        archive_name=archive[1],
        archive_url=archive[2],
        manifest_asset_id=manifest[0],
        manifest_name=manifest[1],
        manifest_url=manifest[2],
    )


__all__ = ("select_release_identity",)
