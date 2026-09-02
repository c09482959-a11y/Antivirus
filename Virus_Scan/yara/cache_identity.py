"""Immutable compiled-cache identity bound to YARA source and compiler evidence."""
from __future__ import annotations

from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from dataclasses import dataclass
import hashlib
import importlib.metadata
import json
import platform
import sys
import sysconfig
from types import ModuleType

from Virus_Scan.contracts.no_hook_materialization import no_hook_plain_instance_dict
from Virus_Scan.yara.source import YaraRuleSource
from Virus_Scan.yara.validation import bounded_int, release_tag, sha256_text, version_text
from Virus_Scan.yara.versioning import (
    YARA_ARCHIVE_POLICY_VERSION,
    YARA_CACHE_SCHEMA_VERSION,
    YARA_COMPILE_POLICY_VERSION,
    YARA_MANIFEST_GRAMMAR_VERSION,
    YARA_PARTITION_VERSION,
    YARA_RELEASE_CONTRACT_VERSION,
)


def _module_text(module: object, name: str) -> str:
    if type(name) is not str:
        return "unavailable"
    if type(module) is ModuleType:
        data = object.__getattribute__(module, "__dict__")
    else:
        data = no_hook_plain_instance_dict(module)
    value = dict.get(data, name) if type(data) is dict else None
    return str.__str__(value) if type(value) is str and value else "unavailable"


def _python_package_version() -> str:
    try:
        value = importlib.metadata.version("yara-python")
    except importlib.metadata.PackageNotFoundError:
        return "unavailable"
    return value if type(value) is str and value else "unavailable"


def _platform_identity() -> str:
    values = (
        sys.implementation.cache_tag or "unknown-cache-tag",
        sysconfig.get_platform(),
        platform.system(),
        platform.machine(),
        int.__str__(sys.version_info.major) + "." + int.__str__(sys.version_info.minor),
    )
    return "|".join(values)


@dataclass(frozen=True, slots=True)
class YaraCompiledCacheIdentity:
    source_trust: str
    package_kind: str
    release_id: int
    release_tag: str
    archive_asset_id: int
    archive_name: str
    manifest_asset_id: int
    manifest_name: str
    archive_sha256: str
    manifest_sha256: str
    member_digests: tuple[tuple[str, str], ...]
    group_index: int
    group_count: int
    yara_python_version: str
    yara_engine_version: str
    platform_identity: str
    release_contract_version: str = YARA_RELEASE_CONTRACT_VERSION
    manifest_grammar_version: str = YARA_MANIFEST_GRAMMAR_VERSION
    archive_policy_version: str = YARA_ARCHIVE_POLICY_VERSION
    cache_schema_version: str = YARA_CACHE_SCHEMA_VERSION
    partition_version: str = YARA_PARTITION_VERSION
    compile_policy_version: str = YARA_COMPILE_POLICY_VERSION

    def __post_init__(self) -> None:
        if type(self) is not YaraCompiledCacheIdentity:
            raise TypeError("yara_cache_identity_owner_invalid")
        trust = exact_bounded_text(self.source_trust, "yara_cache_source_trust_invalid", maximum=32)
        if trust not in ("official_verified", "custom_verified"):
            raise ValueError("yara_cache_source_trust_invalid")
        kind = exact_bounded_text(self.package_kind, "yara_cache_package_kind_invalid", maximum=16)
        if trust == "official_verified":
            if kind not in ("core", "extended", "full"):
                raise ValueError("yara_cache_package_kind_invalid")
            release_identifier = bounded_int(
                self.release_id, "yara_cache_release_id_invalid", minimum=1, maximum=1 << 63
            )
            release_label = release_tag(self.release_tag, "yara_cache_release_tag_invalid")
            archive_asset_identifier = bounded_int(
                self.archive_asset_id, "yara_cache_archive_asset_id_invalid", minimum=1, maximum=1 << 63
            )
            manifest_asset_identifier = bounded_int(
                self.manifest_asset_id, "yara_cache_manifest_asset_id_invalid", minimum=1, maximum=1 << 63
            )
            if archive_asset_identifier == manifest_asset_identifier:
                raise ValueError("yara_cache_release_asset_identity_conflict")
            archive_name = exact_bounded_text(self.archive_name, "yara_cache_archive_name_invalid", maximum=96)
            manifest_name = exact_bounded_text(self.manifest_name, "yara_cache_manifest_name_invalid", maximum=96)
            if archive_name != "yara-forge-rules-" + kind + ".zip":
                raise ValueError("yara_cache_archive_name_invalid")
            if manifest_name != "yara-forge-rules-sha256.txt":
                raise ValueError("yara_cache_manifest_name_invalid")
        else:
            if kind not in ("custom", "core", "extended"):
                raise ValueError("yara_cache_package_kind_invalid")
            if (
                self.release_id != 0
                or self.release_tag != ""
                or self.archive_asset_id != 0
                or self.archive_name != ""
                or self.manifest_asset_id != 0
                or self.manifest_name != ""
            ):
                raise ValueError("yara_cache_custom_release_identity_invalid")
            release_identifier = 0
            release_label = ""
            archive_asset_identifier = 0
            archive_name = ""
            manifest_asset_identifier = 0
            manifest_name = ""
        archive = sha256_text(self.archive_sha256, "yara_cache_archive_sha256_invalid")
        manifest = self.manifest_sha256
        if type(manifest) is not str:
            raise TypeError("yara_cache_manifest_sha256_invalid")
        manifest = str.__str__(manifest)
        if trust == "official_verified":
            manifest = sha256_text(manifest, "yara_cache_manifest_sha256_invalid")
        elif manifest != "":
            raise ValueError("yara_cache_custom_manifest_invalid")
        if type(self.member_digests) is not tuple or not self.member_digests:
            raise TypeError("yara_cache_members_invalid")
        normalized: list[tuple[str, str]] = []
        for item in self.member_digests:
            if type(item) is not tuple or len(item) != 2:
                raise TypeError("yara_cache_member_invalid")
            normalized.append((
                exact_bounded_text(item[0], "yara_cache_member_name_invalid", maximum=4096),
                sha256_text(item[1], "yara_cache_member_sha256_invalid"),
            ))
        members = tuple(normalized)
        if members != tuple(sorted(set(members))):
            raise ValueError("yara_cache_members_order_invalid")
        group_count = bounded_int(self.group_count, "yara_cache_group_count_invalid", minimum=1, maximum=1024)
        group_index = bounded_int(self.group_index, "yara_cache_group_index_invalid", maximum=group_count - 1)
        object.__setattr__(self, "source_trust", trust)
        object.__setattr__(self, "package_kind", kind)
        object.__setattr__(self, "release_id", release_identifier)
        object.__setattr__(self, "release_tag", release_label)
        object.__setattr__(self, "archive_asset_id", archive_asset_identifier)
        object.__setattr__(self, "archive_name", archive_name)
        object.__setattr__(self, "manifest_asset_id", manifest_asset_identifier)
        object.__setattr__(self, "manifest_name", manifest_name)
        object.__setattr__(self, "archive_sha256", archive)
        object.__setattr__(self, "manifest_sha256", manifest)
        object.__setattr__(self, "member_digests", members)
        object.__setattr__(self, "group_index", group_index)
        object.__setattr__(self, "group_count", group_count)
        for field in (
            "yara_python_version", "yara_engine_version",
            "release_contract_version", "manifest_grammar_version",
            "archive_policy_version", "cache_schema_version",
            "partition_version", "compile_policy_version",
        ):
            object.__setattr__(self, field, version_text(object.__getattribute__(self, field)))
        object.__setattr__(
            self,
            "platform_identity",
            exact_bounded_text(self.platform_identity, "yara_platform_identity_invalid", maximum=256),
        )

    def payload(self) -> dict[str, object]:
        return {
            "archive_asset_id": self.archive_asset_id,
            "archive_name": self.archive_name,
            "archive_policy_version": self.archive_policy_version,
            "archive_sha256": self.archive_sha256,
            "cache_schema_version": self.cache_schema_version,
            "compile_policy_version": self.compile_policy_version,
            "group_count": self.group_count,
            "group_index": self.group_index,
            "manifest_asset_id": self.manifest_asset_id,
            "manifest_grammar_version": self.manifest_grammar_version,
            "manifest_name": self.manifest_name,
            "manifest_sha256": self.manifest_sha256,
            "member_digests": [list(item) for item in self.member_digests],
            "package_kind": self.package_kind,
            "partition_version": self.partition_version,
            "platform_identity": self.platform_identity,
            "release_contract_version": self.release_contract_version,
            "release_id": self.release_id,
            "release_tag": self.release_tag,
            "source_trust": self.source_trust,
            "yara_engine_version": self.yara_engine_version,
            "yara_python_version": self.yara_python_version,
        }

    @property
    def digest(self) -> str:
        raw = json.dumps(self.payload(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()



def cache_identity_from_payload(value: object) -> YaraCompiledCacheIdentity:
    if type(value) is not dict:
        raise TypeError("yara_cache_identity_payload_invalid")
    expected = {
        "archive_asset_id", "archive_name", "archive_policy_version",
        "archive_sha256", "cache_schema_version", "compile_policy_version",
        "group_count", "group_index", "manifest_asset_id",
        "manifest_grammar_version", "manifest_name", "manifest_sha256",
        "member_digests", "package_kind", "partition_version",
        "platform_identity", "release_contract_version", "release_id",
        "release_tag", "source_trust", "yara_engine_version",
        "yara_python_version",
    }
    if set(value) != expected:
        raise ValueError("yara_cache_identity_payload_fields_invalid")
    raw_members = dict.get(value, "member_digests")
    if type(raw_members) is not list:
        raise TypeError("yara_cache_identity_members_payload_invalid")
    members: list[tuple[str, str]] = []
    for item in raw_members:
        if type(item) is not list or len(item) != 2:
            raise TypeError("yara_cache_identity_member_payload_invalid")
        members.append((item[0], item[1]))
    return YaraCompiledCacheIdentity(
        source_trust=dict.get(value, "source_trust"),
        package_kind=dict.get(value, "package_kind"),
        release_id=dict.get(value, "release_id"),
        release_tag=dict.get(value, "release_tag"),
        archive_asset_id=dict.get(value, "archive_asset_id"),
        archive_name=dict.get(value, "archive_name"),
        manifest_asset_id=dict.get(value, "manifest_asset_id"),
        manifest_name=dict.get(value, "manifest_name"),
        archive_sha256=dict.get(value, "archive_sha256"),
        manifest_sha256=dict.get(value, "manifest_sha256"),
        member_digests=tuple(members),
        group_index=dict.get(value, "group_index"),
        group_count=dict.get(value, "group_count"),
        yara_python_version=dict.get(value, "yara_python_version"),
        yara_engine_version=dict.get(value, "yara_engine_version"),
        platform_identity=dict.get(value, "platform_identity"),
        release_contract_version=dict.get(value, "release_contract_version"),
        manifest_grammar_version=dict.get(value, "manifest_grammar_version"),
        archive_policy_version=dict.get(value, "archive_policy_version"),
        cache_schema_version=dict.get(value, "cache_schema_version"),
        partition_version=dict.get(value, "partition_version"),
        compile_policy_version=dict.get(value, "compile_policy_version"),
    )

def build_cache_identity(
    source: YaraRuleSource,
    yara_module: object,
    *,
    group_index: int = 0,
    group_count: int = 1,
) -> YaraCompiledCacheIdentity:
    if type(source) is not YaraRuleSource or not source.cache_allowed:
        raise TypeError("yara_cache_source_identity_invalid")
    validated_group_count = bounded_int(
        group_count, "yara_cache_group_count_invalid", minimum=1, maximum=1024
    )
    validated_group_index = bounded_int(
        group_index,
        "yara_cache_group_index_invalid",
        maximum=validated_group_count - 1,
    )
    selected = tuple(
        (member.name, member.sha256)
        for ordinal, member in enumerate(source.members)
        if ordinal % validated_group_count == validated_group_index
    )
    if not selected:
        raise ValueError("yara_cache_group_members_empty")
    release_identity = (
        source.acquisition.snapshot.identity
        if source.trust_state == "official_verified" and source.acquisition is not None
        else None
    )
    return YaraCompiledCacheIdentity(
        source_trust=source.trust_state,
        package_kind=source.package_kind,
        release_id=0 if release_identity is None else release_identity.release_id,
        release_tag="" if release_identity is None else release_identity.release_tag,
        archive_asset_id=0 if release_identity is None else release_identity.archive_asset_id,
        archive_name="" if release_identity is None else release_identity.archive_name,
        manifest_asset_id=0 if release_identity is None else release_identity.manifest_asset_id,
        manifest_name="" if release_identity is None else release_identity.manifest_name,
        archive_sha256=source.archive_sha256,
        manifest_sha256=source.manifest_sha256,
        member_digests=selected,
        group_index=validated_group_index,
        group_count=validated_group_count,
        yara_python_version=_python_package_version(),
        yara_engine_version=_module_text(yara_module, "__version__"),
        platform_identity=_platform_identity(),
    )


__all__ = ("YaraCompiledCacheIdentity", "build_cache_identity", "cache_identity_from_payload")
