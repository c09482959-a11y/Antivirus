"""Canonical YARA compilation and partial-acceptance policy owner."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
import tempfile
import zipfile

from Virus_Scan.core.paths import safe_extract_zip_member
from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.yara.cache_identity import YaraCompiledCacheIdentity
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.contracts import YaraRuleLoadResult
from Virus_Scan.yara.no_hook import yara_exception_text
from Virus_Scan.yara.optional_dependency import yara_compile
from Virus_Scan.yara.source import YaraRuleSource


@dataclass(frozen=True, slots=True)
class YaraCompilationOutcome:
    rules: object
    load_result: YaraRuleLoadResult
    cache_identity: YaraCompiledCacheIdentity

    def __post_init__(self) -> None:
        if type(self) is not YaraCompilationOutcome:
            raise TypeError("yara_compilation_outcome_owner_invalid")
        if type(self.load_result) is not YaraRuleLoadResult:
            raise TypeError("yara_compilation_load_result_invalid")
        if type(self.cache_identity) is not YaraCompiledCacheIdentity:
            raise TypeError("yara_compilation_cache_identity_invalid")
        if self.load_result.ready and self.rules is None:
            raise ValueError("yara_compilation_ready_rules_missing")
        if not self.load_result.ready and self.rules is not None:
            raise ValueError("yara_compilation_unready_rules_present")



def yara_rule_namespace(name: str) -> str:
    digest = sha256(name.encode("utf-8")).hexdigest()[:16]
    base = re.sub("[^A-Za-z0-9_]+", "_", name)[-96:]
    return base + "_" + digest


def _selected_names(identity: YaraCompiledCacheIdentity) -> tuple[str, ...]:
    return tuple(item[0] for item in identity.member_digests)


def _extract_selected(source: YaraRuleSource, identity: YaraCompiledCacheIdentity) -> tuple[dict[str, str], object | None]:
    selected = _selected_names(identity)
    if source.path.suffix.lower() != ".zip":
        if len(selected) != 1 or selected[0] != source.path.name:
            raise ValueError("yara_custom_source_member_identity_mismatch")
        return {yara_rule_namespace(selected[0]): str(source.path)}, None
    temporary = tempfile.TemporaryDirectory(prefix="umige-yara-compile-")
    filepaths: dict[str, str] = {}
    try:
        with zipfile.ZipFile(source.path, "r") as archive:
            infos = archive.infolist()
            for name in selected:
                matches = tuple(info for info in infos if type(info) is zipfile.ZipInfo and info.filename == name)
                if len(matches) != 1:
                    raise ValueError("yara_compile_member_missing")
                extracted = safe_extract_zip_member(archive, matches[0], temporary.name)
                if type(extracted) is not str or not Path(extracted).is_file():
                    raise ValueError("yara_compile_member_extract_failed")
                filepaths[yara_rule_namespace(name)] = extracted
    except SCAN_CONTENT_ERRORS:
        temporary.cleanup()
        raise
    if len(filepaths) != len(selected):
        temporary.cleanup()
        raise ValueError("yara_compile_member_set_incomplete")
    return filepaths, temporary


def _load_result(
    state: str,
    *,
    ready: bool,
    total: int,
    compiled: int,
    threshold: float,
    failures: tuple[str, ...] = (),
    reason: str = "",
) -> YaraRuleLoadResult:
    return YaraRuleLoadResult(
        state=state,
        ready=ready,
        total_members=total,
        compiled_members=compiled,
        failed_members=total - compiled,
        acceptance_threshold=threshold,
        failure_samples=tuple(sorted(set(failures)))[:32],
        reason=reason,
    )


def compile_rule_source(
    source: YaraRuleSource,
    config: YaraConfig,
    identity: YaraCompiledCacheIdentity,
    yara_module: object,
) -> YaraCompilationOutcome:
    if type(source) is not YaraRuleSource or type(config) is not YaraConfig:
        raise TypeError("yara_compile_contract_invalid")
    if type(identity) is not YaraCompiledCacheIdentity:
        raise TypeError("yara_compile_identity_invalid")
    total = len(identity.member_digests)
    threshold = config.partial_compile_threshold
    filepaths, temporary = _extract_selected(source, identity)
    namespace_names = {yara_rule_namespace(name): name for name in _selected_names(identity)}
    if set(namespace_names) != set(filepaths):
        if temporary is not None:
            temporary.cleanup()
        raise ValueError("yara_compile_namespace_identity_mismatch")
    try:
        try:
            rules = yara_compile(yara_module, filepaths=filepaths)
        except SCAN_CONTENT_ERRORS:
            accepted: dict[str, str] = {}
            failures: list[str] = []
            for namespace in tuple(sorted(filepaths)):
                try:
                    yara_compile(yara_module, filepaths={namespace: filepaths[namespace]})
                except SCAN_CONTENT_ERRORS:
                    failures.append(namespace_names[namespace])
                else:
                    accepted[namespace] = filepaths[namespace]
            compiled_count = len(accepted)
            ratio = float(compiled_count) / float(total)
            if compiled_count == 0 or ratio < threshold:
                result = _load_result(
                    "partial_rejected", ready=False, total=total,
                    compiled=compiled_count, threshold=threshold,
                    failures=tuple(failures), reason="partial_compile_threshold_not_met",
                )
                return YaraCompilationOutcome(None, result, identity)
            try:
                rules = yara_compile(yara_module, filepaths=accepted)
            except SCAN_CONTENT_ERRORS as final_error:
                reason = "partial_compile_final_failure:" + yara_exception_text(final_error)[:160]
                result = _load_result(
                    "partial_rejected", ready=False, total=total,
                    compiled=compiled_count, threshold=threshold,
                    failures=tuple(failures), reason=reason,
                )
                return YaraCompilationOutcome(None, result, identity)
            result = _load_result(
                "partially_compiled_accepted", ready=True, total=total,
                compiled=compiled_count, threshold=threshold,
                failures=tuple(failures), reason="",
            )
            return YaraCompilationOutcome(rules, result, identity)
        state = "custom_verified" if source.trust_state == "custom_verified" else "fully_compiled"
        result = _load_result(
            state, ready=True, total=total, compiled=total,
            threshold=threshold, reason="",
        )
        return YaraCompilationOutcome(rules, result, identity)
    finally:
        if temporary is not None:
            temporary.cleanup()


__all__ = ("YaraCompilationOutcome", "compile_rule_source", "yara_rule_namespace")
