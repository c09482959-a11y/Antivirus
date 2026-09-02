"""External Mitre cache layout and atomic local-state materialization."""
from __future__ import annotations

import json
import os
from pathlib import Path, PosixPath, WindowsPath
import tempfile

from Virus_Scan.runtime.api import (
    durable_replace_regular_file,
    flush_open_writable_file,
)

from Virus_Scan.detection.attack.config import config_readme, config_schema_json, config_toml
from Virus_Scan.detection.attack.versioning import ATTACK_CACHE_STATE_VERSION

_PATH_TYPES = (Path, PosixPath, WindowsPath)
_MAX_STATE_BYTES = 1024 * 1024
_BUNDLE_PREFIX = "enterprise-attack-v"
_BUNDLE_SUFFIX = ".json"

CONFIG_NAME = "mitre_config.toml"
SCHEMA_NAME = "mitre_config.schema.json"
DEFAULTS_NAME = "mitre_defaults.toml"
README_NAME = "README.md"
LOCK_NAME = ".umige-mitre.lock"
STATE_NAME = "mitre_state.json"
INDEX_NAME = "enterprise-attack-index.json"
NOTICE_NAME = "NOTICE.txt"


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in out:
            raise ValueError("attack_state_duplicate_json_key")
        out[str.__str__(key)] = value
    return out


def _reject_constant(_value: str) -> object:
    raise ValueError("attack_state_nonfinite_json_value")


def cache_paths(root: Path) -> dict[str, Path]:
    if type(root) not in _PATH_TYPES:
        raise TypeError("attack_cache_root_required")
    return {
        "config": root / CONFIG_NAME, "defaults": root / DEFAULTS_NAME,
        "schema": root / SCHEMA_NAME, "readme": root / README_NAME, "lock": root / LOCK_NAME,
        "state": root / STATE_NAME, "index": root / INDEX_NAME,
        "notice": root / NOTICE_NAME,
    }


def promote_file(source: Path, destination: Path) -> None:
    if type(source) not in _PATH_TYPES or type(destination) not in _PATH_TYPES:
        raise TypeError("attack_promotion_path_invalid")
    if source.parent != destination.parent or not source.is_file():
        raise ValueError("attack_promotion_source_invalid")
    durable_replace_regular_file(source, destination)


def atomic_write(path: Path, data: bytes, *, replace: bool = True) -> None:
    if type(path) not in _PATH_TYPES or type(data) is not bytes or type(replace) is not bool:
        raise TypeError("attack_atomic_write_input_invalid")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not replace:
        return
    fd, temp_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            flush_open_writable_file(handle.fileno())
        if path.exists() and not replace:
            return
        promote_file(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def ensure_generated_controls(root: Path) -> dict[str, Path]:
    if type(root) not in _PATH_TYPES:
        raise TypeError("attack_cache_root_required")
    root.mkdir(parents=True, exist_ok=True)
    paths = cache_paths(root)
    atomic_write(paths["config"], config_toml().encode("utf-8"), replace=False)
    atomic_write(paths["defaults"], config_toml().encode("utf-8"), replace=False)
    atomic_write(paths["schema"], config_schema_json().encode("utf-8"), replace=False)
    atomic_write(paths["readme"], config_readme().encode("utf-8"), replace=False)
    return paths


def write_state(path: Path, record: dict[str, object]) -> None:
    if type(record) is not dict:
        raise TypeError("attack_state_record_required")
    payload = dict(record)
    payload["state_version"] = ATTACK_CACHE_STATE_VERSION
    atomic_write(path, (json.dumps(payload, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8"))


def load_state(path: Path) -> dict[str, object] | None:
    if type(path) not in _PATH_TYPES or not path.is_file():
        return None
    try:
        if path.stat().st_size > _MAX_STATE_BYTES:
            return None
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None
    if type(value) is not dict or dict.get(value, "state_version") != ATTACK_CACHE_STATE_VERSION:
        return None
    return value


def bundle_identity_from_path(path: Path) -> str | None:
    if type(path) not in _PATH_TYPES:
        return None
    name = path.name
    if not name.startswith(_BUNDLE_PREFIX) or not name.endswith(_BUNDLE_SUFFIX):
        return None
    identity = name[len(_BUNDLE_PREFIX):-len(_BUNDLE_SUFFIX)]
    if len(identity) != 40 or any(ch not in "0123456789abcdef" for ch in identity):
        return None
    return identity


def active_bundle_path(root: Path, state: dict[str, object] | None) -> Path | None:
    if type(root) not in _PATH_TYPES or type(state) is not dict:
        return None
    name = dict.get(state, "active_bundle")
    if type(name) is not str or "/" in name or "\\" in name:
        return None
    path = root / str.__str__(name)
    if bundle_identity_from_path(path) is None:
        return None
    return path if path.is_file() else None


__all__ = (
    "DEFAULTS_NAME", "INDEX_NAME", "LOCK_NAME", "NOTICE_NAME", "README_NAME", "SCHEMA_NAME", "STATE_NAME", "active_bundle_path",
    "atomic_write", "bundle_identity_from_path", "cache_paths",
    "ensure_generated_controls", "load_state", "promote_file", "write_state",
)
