"""Canonical compiled YARA cache identity, persistence, and admission owner."""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path, PosixPath, WindowsPath
import secrets
import stat

from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS, SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.resource_paths import yara_dir
from Virus_Scan.yara.cache_identity import (
    YaraCompiledCacheIdentity,
    cache_identity_from_payload,
)
from Virus_Scan.yara.contracts import YaraRuleLoadResult
from Virus_Scan.yara.integrity import file_sha256
from Virus_Scan.yara.optional_dependency import yara_load
from Virus_Scan.runtime.api import (
    durable_replace_regular_file,
    flush_open_writable_file,
    path_contains_filesystem_alias,
    stat_result_is_filesystem_alias,
)

_PATH_TYPES = (Path, PosixPath, WindowsPath)
_MAX_CACHE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_MANIFEST_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class YaraCachePaths:
    root: Path
    compiled: Path
    manifest: Path

    def __post_init__(self) -> None:
        if type(self) is not YaraCachePaths:
            raise TypeError("yara_cache_paths_owner_invalid")
        if type(self.root) not in _PATH_TYPES or type(self.compiled) not in _PATH_TYPES or type(self.manifest) not in _PATH_TYPES:
            raise TypeError("yara_cache_paths_invalid")
        if self.compiled.parent != self.root or self.manifest.parent != self.root:
            raise ValueError("yara_cache_paths_parent_invalid")


@dataclass(frozen=True, slots=True)
class YaraCachedRules:
    rules: object
    load_result: YaraRuleLoadResult
    identity: YaraCompiledCacheIdentity
    paths: YaraCachePaths

    def __post_init__(self) -> None:
        if type(self) is not YaraCachedRules or self.rules is None:
            raise TypeError("yara_cached_rules_owner_invalid")
        if type(self.load_result) is not YaraRuleLoadResult or not self.load_result.ready:
            raise ValueError("yara_cached_load_result_invalid")
        if type(self.identity) is not YaraCompiledCacheIdentity or type(self.paths) is not YaraCachePaths:
            raise TypeError("yara_cached_identity_invalid")


def cache_paths(identity: YaraCompiledCacheIdentity, *, root: Path | None = None) -> YaraCachePaths:
    if type(identity) is not YaraCompiledCacheIdentity:
        raise TypeError("yara_cache_identity_required")
    base = Path(yara_dir()) if root is None else root
    if type(base) not in _PATH_TYPES:
        raise TypeError("yara_cache_root_invalid")
    cache_name = "yaralight.cache" if identity.package_kind == "core" else "yara.cache"
    directory = base / cache_name
    if identity.group_count > 1:
        directory = directory / "groups"
    stem = "compiled-" + identity.digest
    return YaraCachePaths(directory, directory / (stem + ".yarc"), directory / (stem + ".json"))


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if type(key) is not str or key in value:
            raise ValueError("yara_cache_manifest_duplicate_key")
        value[str.__str__(key)] = item
    return value


def _reject_constant(_value: str) -> object:
    raise ValueError("yara_cache_manifest_nonfinite")


def _load_result_payload(result: YaraRuleLoadResult) -> dict[str, object]:
    return {
        "acceptance_threshold": result.acceptance_threshold,
        "compile_policy_version": result.compile_policy_version,
        "compiled_members": result.compiled_members,
        "failed_members": result.failed_members,
        "failure_samples": list(result.failure_samples),
        "ready": result.ready,
        "reason": result.reason,
        "state": result.state,
        "total_members": result.total_members,
    }


def _load_result_from_payload(value: object) -> YaraRuleLoadResult:
    if type(value) is not dict:
        raise TypeError("yara_cache_load_result_payload_invalid")
    expected = {
        "acceptance_threshold", "compile_policy_version", "compiled_members",
        "failed_members", "failure_samples", "ready", "reason", "state",
        "total_members",
    }
    if set(value) != expected or type(dict.get(value, "failure_samples")) is not list:
        raise ValueError("yara_cache_load_result_fields_invalid")
    return YaraRuleLoadResult(
        state=dict.get(value, "state"),
        ready=dict.get(value, "ready"),
        total_members=dict.get(value, "total_members"),
        compiled_members=dict.get(value, "compiled_members"),
        failed_members=dict.get(value, "failed_members"),
        acceptance_threshold=dict.get(value, "acceptance_threshold"),
        failure_samples=tuple(dict.get(value, "failure_samples")),
        reason=dict.get(value, "reason"),
        compile_policy_version=dict.get(value, "compile_policy_version"),
    )


def _manifest_payload(identity: YaraCompiledCacheIdentity, result: YaraRuleLoadResult, paths: YaraCachePaths, compiled_sha256: str) -> dict[str, object]:
    return {
        "compiled_filename": paths.compiled.name,
        "compiled_sha256": compiled_sha256,
        "identity": identity.payload(),
        "identity_digest": identity.digest,
        "load_result": _load_result_payload(result),
    }


def _manifest_json_safe(value: object) -> object:
    if type(value) is dict:
        safe: dict[str, object] = {}
        for key, item in dict.items(value):
            if type(key) is not str or key in safe:
                raise TypeError("yara_cache_manifest_key_invalid")
            safe[str.__str__(key)] = _manifest_json_safe(item)
        return safe
    if type(value) in (list, tuple):
        return [_manifest_json_safe(item) for item in value]
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        if math.isfinite(value):
            return value
        return {"non_finite_float": float.__str__(value)}
    raise TypeError("yara_cache_manifest_value_invalid")


def _manifest_path(path: object) -> Path:
    if type(path) is str:
        path_text = str.__str__(path)
        if not path_text or "\x00" in path_text:
            raise TypeError("yara_cache_manifest_path_invalid")
        return Path(path_text)
    if type(path) in _PATH_TYPES:
        return path
    raise TypeError("yara_cache_manifest_path_invalid")


def _cache_directory_chain(paths: YaraCachePaths) -> tuple[Path, ...]:
    if paths.root.name == "groups":
        return (paths.root.parent.parent, paths.root.parent, paths.root)
    return (paths.root.parent, paths.root)


def _validate_cache_tree(paths: YaraCachePaths, *, create: bool) -> bool:
    for index, directory in enumerate(_cache_directory_chain(paths)):
        if create:
            if path_contains_filesystem_alias(directory.parent):
                raise ValueError("yara_cache_directory_invalid")
            if index == 0:
                directory.mkdir(parents=True, exist_ok=True)
            else:
                directory.mkdir(exist_ok=True)
        try:
            state = directory.lstat()
        except FileNotFoundError:
            return False
        if (
            path_contains_filesystem_alias(directory)
            or stat_result_is_filesystem_alias(state)
            or not stat.S_ISDIR(state.st_mode)
        ):
            raise ValueError("yara_cache_directory_invalid")
    return True


def _existing_regular(path: Path) -> bool:
    try:
        state = path.lstat()
    except FileNotFoundError:
        return False
    if (
        path_contains_filesystem_alias(path)
        or stat_result_is_filesystem_alias(state)
        or not stat.S_ISREG(state.st_mode)
    ):
        raise ValueError("yara_cache_file_invalid")
    return True


def _read_regular_bytes(path: Path, *, minimum: int, maximum: int) -> bytes:
    try:
        initial = path.lstat()
    except OSError as exc:
        raise ValueError("yara_cache_file_invalid") from exc
    if (
        path_contains_filesystem_alias(path)
        or stat_result_is_filesystem_alias(initial)
        or not stat.S_ISREG(initial.st_mode)
        or initial.st_size < minimum
        or initial.st_size > maximum
    ):
        raise ValueError("yara_cache_file_invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino)
        ):
            raise ValueError("yara_cache_file_invalid")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        if len(data) < minimum or len(data) > maximum:
            raise ValueError("yara_cache_file_invalid")
    finally:
        os.close(descriptor)
    try:
        final = path.lstat()
    except OSError as exc:
        raise ValueError("yara_cache_file_invalid") from exc
    if (
        path_contains_filesystem_alias(path)
        or stat_result_is_filesystem_alias(final)
        or not stat.S_ISREG(final.st_mode)
        or (final.st_dev, final.st_ino) != (initial.st_dev, initial.st_ino)
    ):
        raise ValueError("yara_cache_file_invalid")
    return data


def _write_manifest_json_atomic(path: object, obj: object) -> bool:
    if type(obj) is not dict:
        raise TypeError("yara_cache_manifest_write_contract_invalid")
    manifest_path = _manifest_path(path)
    if path_contains_filesystem_alias(manifest_path.parent.parent):
        raise ValueError("yara_cache_directory_invalid")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    parent_state = manifest_path.parent.lstat()
    if (
        path_contains_filesystem_alias(manifest_path.parent)
        or stat_result_is_filesystem_alias(parent_state)
        or not stat.S_ISDIR(parent_state.st_mode)
    ):
        raise ValueError("yara_cache_directory_invalid")
    _existing_regular(manifest_path)
    temporary = manifest_path.with_name(manifest_path.name + ".tmp-" + secrets.token_hex(16))
    data = json.dumps(
        _manifest_json_safe(obj),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(data) > _MAX_MANIFEST_BYTES:
        raise ValueError("yara_cache_manifest_oversized")
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            flush_open_writable_file(stream.fileno())
        durable_replace_regular_file(temporary, manifest_path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return True


def _compiled_save(compiled: object, path: Path) -> None:
    class_dict = type.__getattribute__(type(compiled), "__dict__")
    method = class_dict.get("save")
    if not callable(method):
        raise TypeError("yara_compiled_save_unavailable")
    method(compiled, str(path))


def _discard(paths: YaraCachePaths) -> None:
    for path in (paths.manifest, paths.compiled):
        try:
            path.unlink(missing_ok=True)
        except IO_CONFIGURATION_ERRORS:
            continue


def save_compiled_cache(
    compiled: object,
    identity: YaraCompiledCacheIdentity,
    load_result: YaraRuleLoadResult,
    *,
    root: Path | None = None,
) -> bool:
    if compiled is None or type(identity) is not YaraCompiledCacheIdentity:
        raise TypeError("yara_cache_save_contract_invalid")
    if type(load_result) is not YaraRuleLoadResult or not load_result.ready:
        raise ValueError("yara_cache_save_load_result_invalid")
    paths = cache_paths(identity, root=root)
    temporary = paths.compiled.with_name(paths.compiled.name + ".tmp-" + secrets.token_hex(16))
    tree_safe = False
    try:
        if not _validate_cache_tree(paths, create=True):
            raise ValueError("yara_cache_directory_invalid")
        tree_safe = True
        _existing_regular(paths.compiled)
        _existing_regular(paths.manifest)
        _compiled_save(compiled, temporary)
        if not _existing_regular(temporary) or temporary.lstat().st_size < 1:
            raise ValueError("yara_cache_compiled_temp_invalid")
        digest = file_sha256(temporary, maximum_bytes=_MAX_CACHE_BYTES)
        durable_replace_regular_file(temporary, paths.compiled)
        _write_manifest_json_atomic(paths.manifest, _manifest_payload(identity, load_result, paths, digest))
    except SCAN_CONTENT_ERRORS:
        if tree_safe:
            _discard(paths)
        try:
            temporary.unlink(missing_ok=True)
        except IO_CONFIGURATION_ERRORS:
            return False
        return False
    return True


def load_compiled_cache(
    identity: YaraCompiledCacheIdentity,
    yara_module: object,
    *,
    root: Path | None = None,
) -> YaraCachedRules | None:
    paths = cache_paths(identity, root=root)
    tree_safe = False
    try:
        if not _validate_cache_tree(paths, create=False):
            return None
        tree_safe = True
        if not _existing_regular(paths.manifest) or not _existing_regular(paths.compiled):
            return None
        raw = json.loads(
            _read_regular_bytes(
                paths.manifest, minimum=2, maximum=_MAX_MANIFEST_BYTES,
            ).decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        if type(raw) is not dict or set(raw) != {"compiled_filename", "compiled_sha256", "identity", "identity_digest", "load_result"}:
            raise ValueError("yara_cache_manifest_fields_invalid")
        admitted = cache_identity_from_payload(dict.get(raw, "identity"))
        if admitted != identity or dict.get(raw, "identity_digest") != identity.digest:
            raise ValueError("yara_cache_identity_mismatch")
        if dict.get(raw, "compiled_filename") != paths.compiled.name:
            raise ValueError("yara_cache_filename_mismatch")
        expected_sha = dict.get(raw, "compiled_sha256")
        if type(expected_sha) is not str or file_sha256(paths.compiled, maximum_bytes=_MAX_CACHE_BYTES) != expected_sha:
            raise ValueError("yara_cache_compiled_digest_mismatch")
        load_result = _load_result_from_payload(dict.get(raw, "load_result"))
        rules = yara_load(yara_module, str(paths.compiled))
        return YaraCachedRules(rules, load_result, identity, paths)
    except SCAN_CONTENT_ERRORS:
        if tree_safe:
            _discard(paths)
        return None


__all__ = (
    "YaraCachePaths", "YaraCachedRules", "cache_paths", "load_compiled_cache",
    "save_compiled_cache", "_write_manifest_json_atomic",
)
