"""Canonical selected YARA source/compiler/catalog execution identity."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.runtime.yara_rules_state import YaraLightSnapshot, YaraRulesSnapshot
from Virus_Scan.yara.cache_identity import YaraCompiledCacheIdentity
from Virus_Scan.yara.contracts import YaraRuleLoadResult
from Virus_Scan.yara.source import YaraRuleSource


@dataclass(frozen=True, slots=True)
class YaraExecutionProvenance:
    verified: bool
    source_trust: str
    package_kind: str
    source_digest: str
    compiled_cache_digest: str
    rule_catalog_digest: str
    release_id: int
    release_tag: str
    compile_policy_version: str


def yara_rule_catalog_digest(source: object, identity: object) -> str:
    if type(source) is not YaraRuleSource or type(identity) is not YaraCompiledCacheIdentity:
        return ""
    return canonical_json_sha256({
        "archive_sha256": source.archive_sha256,
        "group_count": identity.group_count,
        "group_index": identity.group_index,
        "member_digests": identity.member_digests,
        "package_kind": source.package_kind,
    })


def canonical_yara_execution_provenance(
    source: object,
    identity: object,
    load_result: object,
) -> YaraExecutionProvenance:
    verified = (
        type(source) is YaraRuleSource
        and type(identity) is YaraCompiledCacheIdentity
        and type(load_result) is YaraRuleLoadResult
        and load_result.ready is True
        and source.trust_state in ("official_verified", "custom_verified")
        and identity.source_trust == source.trust_state
        and identity.archive_sha256 == source.archive_sha256
        and identity.compile_policy_version == load_result.compile_policy_version
    )
    if type(source) is not YaraRuleSource or type(identity) is not YaraCompiledCacheIdentity:
        return YaraExecutionProvenance(
            False, "unavailable", "unavailable", "", "", "", 0, "", "unverified_yara_execution",
        )
    return YaraExecutionProvenance(
        verified=verified,
        source_trust=source.trust_state,
        package_kind=source.package_kind,
        source_digest=source.archive_sha256 if verified else "",
        compiled_cache_digest=identity.digest if verified else "",
        rule_catalog_digest=yara_rule_catalog_digest(source, identity) if verified else "",
        release_id=identity.release_id,
        release_tag=identity.release_tag,
        compile_policy_version=identity.compile_policy_version,
    )


def selected_yara_execution_provenance(compiled_rules: object) -> YaraExecutionProvenance:
    if type(compiled_rules) is YaraRulesSnapshot or type(compiled_rules) is YaraLightSnapshot:
        return canonical_yara_execution_provenance(
            compiled_rules.source,
            compiled_rules.identity,
            compiled_rules.load_result,
        )
    return YaraExecutionProvenance(
        False, "unavailable", "unavailable", "", "", "", 0, "", "unverified_yara_execution",
    )


__all__ = (
    "YaraExecutionProvenance",
    "canonical_yara_execution_provenance",
    "selected_yara_execution_provenance",
    "yara_rule_catalog_digest",
)
