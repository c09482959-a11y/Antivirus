"""Canonical YARA source resolution, cache admission, and rule loading owner."""
from __future__ import annotations

from dataclasses import dataclass
import logging
from pathlib import Path, PosixPath, WindowsPath
from threading import RLock

from Virus_Scan.runtime.yara_rules_state import YaraRulesSnapshot
from Virus_Scan.contracts.env_config import bool_env
from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import path_contains_filesystem_alias
from Virus_Scan.runtime.config_values import runtime_bool
from Virus_Scan.runtime.resource_paths import yara_dir
from Virus_Scan.runtime.yara_rules_state import yara_rules_state
from Virus_Scan.yara.cache import YaraCachedRules, cache_paths, load_compiled_cache, save_compiled_cache
from Virus_Scan.yara.cache_identity import YaraCompiledCacheIdentity, build_cache_identity
from Virus_Scan.yara.compilation import YaraCompilationOutcome, compile_rule_source
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.contracts import YaraRuleLoadResult
from Virus_Scan.yara.download import (
    acquire_official_archive,
    load_verified_official_archive,
    official_artifact_paths,
    official_state_path,
)
from Virus_Scan.yara.no_hook import yara_message
from Virus_Scan.yara.optional_dependency import YARA_IMPORT_ERROR, YARA_MODULE
from Virus_Scan.yara.source import YaraRuleSource, custom_rule_source, official_rule_source

_PATH_TYPES = (Path, PosixPath, WindowsPath)
_FULL_LOCK = RLock()
_LIGHT_LOCK = RLock()
_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class YaraLoadAttempt:
    rules: object | None
    source: YaraRuleSource | None
    identity: YaraCompiledCacheIdentity | None
    load_result: YaraRuleLoadResult
    cache_hit: bool

    def __post_init__(self) -> None:
        if type(self) is not YaraLoadAttempt:
            raise TypeError("yara_load_attempt_owner_invalid")
        if self.source is not None and type(self.source) is not YaraRuleSource:
            raise TypeError("yara_load_attempt_source_invalid")
        if self.identity is not None and type(self.identity) is not YaraCompiledCacheIdentity:
            raise TypeError("yara_load_attempt_identity_invalid")
        if type(self.load_result) is not YaraRuleLoadResult or type(self.cache_hit) is not bool:
            raise TypeError("yara_load_attempt_result_invalid")
        if self.load_result.ready:
            if self.rules is None or self.source is None or self.identity is None:
                raise ValueError("yara_load_attempt_ready_evidence_missing")
        elif self.rules is not None or self.cache_hit:
            raise ValueError("yara_load_attempt_unready_state_invalid")


def _active_config(config: object) -> YaraConfig:
    if type(config) is not YaraConfig:
        raise TypeError("yara_loader_config_owner_invalid")
    return config


def _official_source(package: str, config: YaraConfig, *, allow_download: bool, force_refresh: bool) -> YaraRuleSource | None:
    if (
        type(package) is not str
        or package not in ("extended", "core")
        or type(config) is not YaraConfig
        or type(allow_download) is not bool
        or type(force_refresh) is not bool
    ):
        raise TypeError("yara_official_source_contract_invalid")
    root = Path(yara_dir())
    try:
        acquisition = (
            acquire_official_archive(root, config, package, force_refresh=force_refresh)
            if allow_download
            else load_verified_official_archive(root, config, package)
        )
    except SCAN_CONTENT_ERRORS:
        return None
    return official_rule_source(acquisition)


def _source_for_path(path: Path, config: YaraConfig, package: str) -> YaraRuleSource:
    if type(path) not in _PATH_TYPES:
        raise TypeError("yara_source_path_invalid")
    if type(package) is not str or package not in ("extended", "core"):
        raise TypeError("yara_source_package_invalid")
    for candidate_package in ("extended", "core"):
        try:
            acquisition = load_verified_official_archive(
                path.parent, config, candidate_package,
            )
        except SCAN_CONTENT_ERRORS:
            continue
        if acquisition.snapshot.local_path == path:
            return official_rule_source(acquisition)
    return custom_rule_source(path, config, package_kind=package)


def resolve_rule_source(
    package: str,
    *,
    explicit_path: object = None,
    auto_download: bool,
    force_refresh: bool,
    config: YaraConfig,
) -> YaraRuleSource | None:
    if (
        type(package) is not str
        or package not in ("extended", "core")
        or type(auto_download) is not bool
        or type(force_refresh) is not bool
        or type(config) is not YaraConfig
    ):
        raise TypeError("yara_source_resolution_contract_invalid")
    if explicit_path is not None:
        if type(explicit_path) is not str or explicit_path == "":
            raise TypeError("yara_explicit_source_path_invalid")
        path = Path(str.__str__(explicit_path)).expanduser().absolute()
        return (
            _source_for_path(path, config, package)
            if not path_contains_filesystem_alias(path) and path.is_file()
            else None
        )
    official = _official_source(
        package, config, allow_download=auto_download,
        force_refresh=force_refresh,
    )
    if official is not None:
        return official
    root = Path(yara_dir())
    names = (
        ("rules.yar", "rules.yara")
        if package == "extended"
        else ("rules-light.yar", "rules-light.yara", "yaralight.yar", "yaralight.yara")
    )
    for name in names:
        candidate = root / name
        if candidate.is_file():
            return custom_rule_source(candidate, config, package_kind=package)
    return None


def _load_result(
    state: str,
    config: YaraConfig,
    *,
    source: YaraRuleSource | None,
    reason: str,
) -> YaraRuleLoadResult:
    total = 0 if source is None else len(source.members)
    return YaraRuleLoadResult(
        state=state,
        ready=False,
        total_members=total,
        compiled_members=0,
        failed_members=total,
        acceptance_threshold=config.partial_compile_threshold,
        failure_samples=(),
        reason=reason[:256],
    )


def _loaded_from_cache(cached: YaraCachedRules, source: YaraRuleSource) -> YaraLoadAttempt:
    return YaraLoadAttempt(cached.rules, source, cached.identity, cached.load_result, True)


def _loaded_from_compile(outcome: YaraCompilationOutcome, source: YaraRuleSource) -> YaraLoadAttempt:
    return YaraLoadAttempt(
        outcome.rules, source, outcome.cache_identity, outcome.load_result, False,
    )


def _load_source(
    source: YaraRuleSource,
    config: YaraConfig,
    *,
    use_cache: bool,
    group_index: int = 0,
    group_count: int = 1,
    yara_module: object | None = YARA_MODULE,
    dependency_error: object = YARA_IMPORT_ERROR,
    allow_cache_write: bool = True,
) -> YaraLoadAttempt:
    if type(source) is not YaraRuleSource or type(config) is not YaraConfig:
        raise TypeError("yara_load_source_owner_invalid")
    if type(use_cache) is not bool or type(allow_cache_write) is not bool:
        raise TypeError("yara_cache_write_policy_invalid")
    if source.trust_state == "custom_unverified":
        return YaraLoadAttempt(
            None, source, None,
            _load_result(
                "custom_unverified", config, source=source,
                reason="custom_source_expected_sha256_required",
            ),
            False,
        )
    if yara_module is None:
        reason = yara_message("yara-python unavailable: ", dependency_error)[:256]
        _LOGGER.error(reason)
        return YaraLoadAttempt(
            None, source, None,
            _load_result("dependency_unavailable", config, source=source, reason=reason),
            False,
        )
    identity = build_cache_identity(
        source, yara_module, group_index=group_index, group_count=group_count,
    )
    if use_cache:
        cached = load_compiled_cache(identity, yara_module)
        if cached is not None:
            return _loaded_from_cache(cached, source)
    outcome = compile_rule_source(source, config, identity, yara_module)
    loaded = _loaded_from_compile(outcome, source)
    if loaded.load_result.ready and use_cache and allow_cache_write and source.cache_allowed:
        save_compiled_cache(loaded.rules, identity, loaded.load_result)
    return loaded


def load_attempt_resource_paths(attempt: YaraLoadAttempt) -> tuple[Path, ...]:
    if type(attempt) is not YaraLoadAttempt:
        raise TypeError("yara_load_attempt_paths_owner_invalid")
    paths: list[Path] = []
    source = attempt.source
    if source is not None:
        paths.append(source.path)
        if source.acquisition is not None:
            snapshot = source.acquisition.snapshot
            _archive, manifest = official_artifact_paths(
                source.path.parent, snapshot.identity, snapshot.manifest_sha256,
            )
            paths.extend((
                manifest,
                official_state_path(source.path.parent, snapshot.identity.package_kind),
            ))
    if attempt.identity is not None:
        cached = cache_paths(attempt.identity)
        paths.extend((cached.compiled, cached.manifest))
    unique: list[Path] = []
    seen: set[Path] = set()
    for candidate in paths:
        if not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(candidate)
    return tuple(unique)


def prepare_rule_group_caches(
    source: YaraRuleSource,
    config: YaraConfig,
    group_count: int,
    *,
    use_cache: bool,
) -> tuple[YaraLoadAttempt, ...]:
    if type(source) is not YaraRuleSource or type(config) is not YaraConfig:
        raise TypeError("yara_group_cache_prepare_owner_invalid")
    if type(group_count) is not int or type(group_count) is bool or group_count < 1:
        raise ValueError("yara_group_cache_prepare_count_invalid")
    if type(use_cache) is not bool:
        raise TypeError("yara_group_cache_prepare_policy_invalid")
    if group_count == 1 or not use_cache:
        return ()
    attempts = tuple(
        _load_source(
            source, config, use_cache=True, group_index=index,
            group_count=group_count, allow_cache_write=True,
        )
        for index in range(group_count)
    )
    if any(not attempt.load_result.ready for attempt in attempts):
        raise RuntimeError("yara_group_cache_prepare_failed")
    return attempts


def load_yara_rules(
    rule_path: object = None,
    *,
    auto_download: bool = True,
    use_cache: bool = True,
    force_refresh: bool = False,
    config: YaraConfig,
    allow_cache_write: bool = True,
) -> YaraLoadAttempt:
    if any(type(value) is not bool for value in (auto_download, use_cache, force_refresh, allow_cache_write)):
        raise TypeError("yara_loader_policy_invalid")
    active = _active_config(config)
    owner = yara_rules_state()
    owner.clear_primary_rules()
    with _FULL_LOCK:
        try:
            source = resolve_rule_source(
                "extended", explicit_path=rule_path,
                auto_download=auto_download, force_refresh=force_refresh,
                config=active,
            )
            loaded = (
                YaraLoadAttempt(
                    None, None, None,
                    _load_result(
                        "integrity_failure", active, source=None,
                        reason="yara_rule_source_unavailable",
                    ),
                    False,
                )
                if source is None
                else _load_source(
                    source, active, use_cache=use_cache,
                    allow_cache_write=allow_cache_write,
                )
            )
        except SCAN_CONTENT_ERRORS as error:
            reason = yara_message("YARA load failed: ", error)[:256]
            _LOGGER.error(reason)
            loaded = YaraLoadAttempt(
                None, None, None,
                _load_result("integrity_failure", active, source=None, reason=reason),
                False,
            )
        if not loaded.load_result.ready:
            return loaded
        owner.set_primary_rules(
            loaded.rules, source_path=str(loaded.source.path),
            loaded_count=loaded.load_result.compiled_members,
            source=loaded.source, identity=loaded.identity,
            load_result=loaded.load_result,
        )
        return loaded


def load_yaralight_rules(
    rule_path: object = None,
    *,
    auto_download: bool = True,
    use_cache: bool = True,
    force_refresh: bool = False,
    config: YaraConfig,
    allow_cache_write: bool = True,
) -> YaraLoadAttempt:
    if any(type(value) is not bool for value in (auto_download, use_cache, force_refresh, allow_cache_write)):
        raise TypeError("yara_loader_policy_invalid")
    active = _active_config(config)
    if bool_env("UMIGE_NO_YARA", default=False) or bool_env("UMIGE_NO_YARALIGHT", default=False) or not runtime_bool("YARALIGHT_ENABLED", default=True):
        return YaraLoadAttempt(
            None, None, None,
            _load_result("integrity_failure", active, source=None, reason="yaralight_disabled"),
            False,
        )
    owner = yara_rules_state()
    with _LIGHT_LOCK:
        try:
            source = resolve_rule_source(
                "core", explicit_path=rule_path,
                auto_download=auto_download,
                force_refresh=force_refresh, config=active,
            )
            loaded = (
                YaraLoadAttempt(
                    None, None, None,
                    _load_result(
                        "integrity_failure", active, source=None,
                        reason="yaralight_rule_source_unavailable",
                    ),
                    False,
                )
                if source is None
                else _load_source(
                    source, active, use_cache=use_cache,
                    allow_cache_write=allow_cache_write,
                )
            )
        except SCAN_CONTENT_ERRORS as error:
            reason = yara_message("YARA-light load failed: ", error)[:256]
            _LOGGER.error(reason)
            loaded = YaraLoadAttempt(
                None, None, None,
                _load_result("integrity_failure", active, source=None, reason=reason),
                False,
            )
        if not loaded.load_result.ready:
            owner.set_light_rules(None, False, loaded_count=0)
            return loaded
        owner.set_light_rules(
            loaded.rules, True, loaded_count=loaded.load_result.compiled_members,
            source=loaded.source, identity=loaded.identity,
            load_result=loaded.load_result,
        )
        return loaded



__all__ = (
    "YaraLoadAttempt", "load_attempt_resource_paths",
    "load_yara_rules", "load_yaralight_rules", "prepare_rule_group_caches",
    "resolve_rule_source",
)
