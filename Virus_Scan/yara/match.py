"""Canonical single-pass YARA execution and physical scan-result owner."""
from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from time import perf_counter_ns
import zipfile

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.detection_observation import ObservationSourceLocation
from Virus_Scan.contracts.file_fingerprint import sha256_file
from Virus_Scan.contracts.no_hook_materialization import no_hook_plain_instance_dict
from Virus_Scan.contracts.yara_hits import (
    YaraHit,
    YaraRuleIdentity,
    YaraScanResult,
    canonical_yara_hit_sequence,
    normalize_yara_hits as _normalize_yara_hits,
    normalize_yara_rule_name as _normalize_yara_rule_name,
    yara_expected_behavior as _yara_expected_behavior,
)
from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.yara_rules_state import YaraLightSnapshot, YaraRulesSnapshot
from Virus_Scan.yara.cache_identity import YaraCompiledCacheIdentity
from Virus_Scan.yara.execution_identity import canonical_yara_execution_provenance
from Virus_Scan.yara.compilation import yara_rule_namespace
from Virus_Scan.yara.contracts import YaraRuleLoadResult
from Virus_Scan.yara.no_hook import yara_exception_text, yara_message, yara_text
from Virus_Scan.yara.source import YaraRuleSource
from Virus_Scan.yara.zip_scan import scan_yara_zip_archive

_MAX_MATCHES = 256
_MAX_METADATA_ITEMS = 64
_MAX_TAGS = 32
_LOGGER = logging.getLogger(__name__)


def normalize_yara_rule_name(rule: object) -> object:
    return _normalize_yara_rule_name(rule)


def normalize_yara_hits(yara_hits: object) -> object:
    return _normalize_yara_hits(yara_hits)


def yara_expected_behavior(rule_name: object) -> object:
    return _yara_expected_behavior(rule_name)


def _execution_snapshot(value: object) -> tuple[object, object, object, object]:
    if type(value) is YaraRulesSnapshot:
        return value.rules, value.source, value.identity, value.load_result
    if type(value) is YaraLightSnapshot:
        return value.rules, value.source, value.identity, value.load_result
    return value, None, None, None


def _artifact_identity(path_text: str) -> str:
    return "content_sha256:" + sha256_file(path_text)


def _execution_provenance(
    source: object, identity: object, load_result: object,
) -> tuple[bool, str, str, str, str, int, str, str, str]:
    provenance = canonical_yara_execution_provenance(source, identity, load_result)
    return (
        provenance.verified,
        provenance.source_trust,
        provenance.package_kind,
        provenance.source_digest,
        provenance.compiled_cache_digest,
        provenance.release_id,
        provenance.release_tag,
        provenance.compile_policy_version,
        provenance.rule_catalog_digest,
    )

def _plain_match_field(value: object, name: str) -> object:
    data = no_hook_plain_instance_dict(value)
    if data is not None and name in data:
        return dict.__getitem__(data, name)
    try:
        return object.__getattribute__(value, name)
    except (AttributeError, TypeError):
        return None


def _primitive_metadata(value: object) -> dict[str, object]:
    if type(value) is not dict:
        return {}
    result: dict[str, object] = {}
    for key in sorted(value)[:_MAX_METADATA_ITEMS]:
        item = dict.get(value, key)
        if type(key) is not str or not key or len(key) > 128:
            continue
        if type(item) is str:
            result[key] = str.__str__(item)[:4096]
        elif type(item) in (int, bool):
            result[key] = item
        elif type(item) is float and math.isfinite(item):
            result[key] = item
    return result


def _rule_tags(value: object) -> tuple[str, ...]:
    if type(value) not in (tuple, list):
        return ()
    tags = {
        str.__str__(item)[:128]
        for item in value[:_MAX_TAGS]
        if type(item) is str and str.__str__(item).strip()
    }
    return tuple(sorted(tags))


def _member_for_namespace(identity: object, namespace: str) -> tuple[str, str]:
    if type(identity) is not YaraCompiledCacheIdentity:
        return "", namespace
    mapping = {yara_rule_namespace(name): name for name, _digest in identity.member_digests}
    if namespace and namespace in mapping:
        return mapping[namespace], namespace
    if len(mapping) == 1:
        only_namespace = next(iter(mapping))
        return mapping[only_namespace], only_namespace
    return "", namespace


def _rule_identity(
    match: object,
    *,
    verified_execution: bool,
    package_kind: str,
    source_digest: str,
    cache_digest: str,
    catalog_digest: str,
    identity: object,
) -> YaraRuleIdentity | None:
    rule_name = _normalize_yara_rule_name(_plain_match_field(match, "rule"))
    if not rule_name:
        return None
    namespace_value = _plain_match_field(match, "namespace")
    namespace = str.__str__(namespace_value)[:160] if type(namespace_value) is str else ""
    source_member, namespace = _member_for_namespace(identity, namespace)
    metadata = _primitive_metadata(_plain_match_field(match, "meta"))
    metadata_id = dict.get(metadata, "id")
    logic_hash = dict.get(metadata, "logic_hash")
    metadata_id = str.__str__(metadata_id)[:160] if type(metadata_id) is str else ""
    logic_hash = str.__str__(logic_hash).lower() if type(logic_hash) is str else ""
    if len(logic_hash) != 64 or any(ch not in "0123456789abcdef" for ch in logic_hash):
        logic_hash = ""
    tags = _rule_tags(_plain_match_field(match, "tags"))
    semantic_metadata = {
        key: dict.__getitem__(metadata, key) for key in metadata
        if key not in {"date", "modified", "created", "author", "reference"}
    }
    metadata_digest = canonical_json_sha256(semantic_metadata) if semantic_metadata else ""
    source_bound = verified_execution and bool(source_member and namespace)
    return YaraRuleIdentity(
        package_kind=package_kind if source_bound else "unavailable",
        rule_source_digest=source_digest if source_bound else "",
        compiled_cache_digest=cache_digest if source_bound else "",
        rule_catalog_digest=catalog_digest if source_bound else "",
        source_member=source_member if source_bound else "",
        compiler_namespace=namespace if source_bound else "",
        rule_name=rule_name,
        metadata_id=metadata_id,
        logic_hash=logic_hash,
        semantic_metadata_digest=metadata_digest,
        rule_tags=tags,
    )


def _root_identity(
    *,
    artifact_identity: str,
    location: ObservationSourceLocation,
    rule_identity: YaraRuleIdentity,
) -> str:
    return "obs_" + canonical_json_sha256({
        "artifact_identity": artifact_identity,
        "rule_identity_digest": rule_identity.digest,
        "source_location": location.to_record(),
    })


def _scan_pass_id(
    *, artifact_identity: str, archive_member: str, package_kind: str,
    source_digest: str, cache_digest: str, catalog_digest: str,
) -> str:
    return "yscan_" + canonical_json_sha256({
        "archive_member": archive_member,
        "artifact_identity": artifact_identity,
        "cache_digest": cache_digest,
        "catalog_digest": catalog_digest,
        "package_kind": package_kind,
        "source_digest": source_digest,
    })


def _match_result(
    matches: object,
    *,
    artifact_path: str,
    archive_member: str,
    source: object,
    identity: object,
    load_result: object,
) -> YaraScanResult:
    if type(matches) in (tuple, list):
        sequence = tuple(matches)
    elif type(matches) in (set, frozenset):
        sequence = tuple(matches)
    else:
        try:
            sequence = tuple(matches)
        except TypeError:
            sequence = (matches,)
    artifact = _artifact_identity(artifact_path)
    (
        verified, source_trust, package_kind, source_digest, cache_digest,
        release_id, release_tag, policy_version, catalog_digest,
    ) = _execution_provenance(source, identity, load_result)
    candidates: list[YaraHit] = []
    failures: set[str] = set()
    for match in sequence:
        rule_identity = _rule_identity(
            match,
            verified_execution=verified,
            package_kind=package_kind,
            source_digest=source_digest,
            cache_digest=cache_digest,
            catalog_digest=catalog_digest,
            identity=identity,
        )
        if rule_identity is None:
            failures.add("yara_match_rule_identity_unavailable")
            continue
        integrity = "verified" if verified and rule_identity.verified_source_bound else "unverified"
        location = ObservationSourceLocation(
            "yara_match",
            locator=artifact_path,
            archive_member=archive_member,
            event_id=rule_identity.digest,
        )
        root = _root_identity(
            artifact_identity=artifact,
            location=location,
            rule_identity=rule_identity,
        )
        candidates.append(YaraHit(
            rule_identity=rule_identity,
            root_observation_id=root,
            integrity_status=integrity,
            source_trust=source_trust if source_trust in (
                "official_verified", "custom_verified", "custom_unverified",
            ) else "unavailable",
            release_id=release_id if type(release_id) is int and not isinstance(release_id, bool) else 0,
            release_tag=release_tag if type(release_tag) is str else "",
            compile_policy_version=policy_version if type(policy_version) is str and policy_version else "unverified_yara_execution",
            artifact_identity=artifact,
            source_location=location,
            unavailable_reason="" if integrity == "verified" else "yara_execution_provenance_unverified",
        ))
    ordered, duplicate_count = canonical_yara_hit_sequence(tuple(candidates))
    retained = ordered[:_MAX_MATCHES]
    truncated_count = max(0, len(ordered) - len(retained))
    if truncated_count:
        failures.add("yara_match_retention_limit_exceeded")
        status = "truncated"
    elif failures:
        status = "partial"
    elif retained:
        status = "complete"
    else:
        status = "complete_no_match"
    return YaraScanResult(
        status=status,
        scan_pass_id=_scan_pass_id(
            artifact_identity=artifact,
            archive_member=archive_member,
            package_kind=package_kind,
            source_digest=source_digest,
            cache_digest=cache_digest,
            catalog_digest=catalog_digest,
        ),
        physical_target_identity=artifact,
        package_kind=package_kind,
        rule_source_digest=source_digest,
        compiled_cache_digest=cache_digest,
        rule_catalog_digest=catalog_digest,
        hits=retained,
        total_match_count=len(sequence),
        retained_match_count=len(retained),
        duplicate_match_count=duplicate_count,
        truncated_match_count=truncated_count,
        archive_member_count=1 if archive_member else 0,
        scanned_member_count=1 if archive_member else 0,
        failed_member_count=0,
        failure_reasons=tuple(sorted(failures)),
    )


def _log_scan_metric(
    result: YaraScanResult,
    *,
    elapsed_ns: int,
    engine_match_invoked: bool,
) -> None:
    if type(result) is not YaraScanResult:
        raise TypeError("yara_scan_metric_result_invalid")
    if type(elapsed_ns) is not int or type(elapsed_ns) is bool or elapsed_ns < 0:
        raise TypeError("yara_scan_metric_elapsed_invalid")
    if type(engine_match_invoked) is not bool:
        raise TypeError("yara_scan_metric_invocation_invalid")
    _LOGGER.info(
        "[YARA_SCAN_METRIC] %s",
        json.dumps(
            {
                "duplicate_match_count": result.duplicate_match_count,
                "elapsed_ns": elapsed_ns,
                "engine_match_invoked": engine_match_invoked,
                "package_kind": result.package_kind,
                "retained_match_count": result.retained_match_count,
                "scan_pass_id": result.scan_pass_id,
                "status": result.status,
                "total_match_count": result.total_match_count,
                "truncated_match_count": result.truncated_match_count,
            },
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ),
    )


def _unavailable_result(file_path: object, reason: str, *, status: str) -> YaraScanResult:
    path_text = yara_text(file_path)
    target = _artifact_identity(path_text) if path_text and Path(path_text).is_file() else ""
    digest = canonical_json_sha256({"reason": reason, "status": status, "target": target})
    return YaraScanResult(
        status=status,
        scan_pass_id="yscan_" + digest,
        physical_target_identity=target,
        package_kind="unavailable",
        rule_source_digest="",
        compiled_cache_digest="",
        rule_catalog_digest="",
        hits=(),
        total_match_count=0,
        retained_match_count=0,
        duplicate_match_count=0,
        truncated_match_count=0,
        archive_member_count=0,
        scanned_member_count=0,
        failed_member_count=0,
        unavailable_reason=reason,
    )


def yara_scan(
    file_path: object,
    compiled_rules: object = None,
    *,
    artifact_path: object = None,
    archive_member: object = "",
) -> YaraScanResult:
    scan_text = yara_text(file_path)
    artifact_text = yara_text(artifact_path) if artifact_path is not None else scan_text
    member_text = yara_text(archive_member) if archive_member is not None else ""
    if not scan_text or not Path(scan_text).is_file():
        raise FileNotFoundError(yara_message("YARA scan target does not exist: ", scan_text))
    if compiled_rules is None:
        result = _unavailable_result(
            scan_text, "yara_compiled_rules_unavailable", status="unavailable",
        )
        _log_scan_metric(result, elapsed_ns=0, engine_match_invoked=False)
        return result
    rules, source, identity, load_result = _execution_snapshot(compiled_rules)
    if rules is None:
        result = _unavailable_result(
            scan_text, "yara_compiled_rules_unavailable", status="unavailable",
        )
        _log_scan_metric(result, elapsed_ns=0, engine_match_invoked=False)
        return result
    started_ns = perf_counter_ns()
    try:
        matches = rules.match(scan_text)
    except SCAN_CONTENT_ERRORS as error:
        result = _unavailable_result(
            scan_text,
            "yara_scan_execution_failed:" + yara_exception_text(error)[:320],
            status="failed",
        )
        _log_scan_metric(
            result,
            elapsed_ns=perf_counter_ns() - started_ns,
            engine_match_invoked=True,
        )
        return result
    result = _match_result(
        matches,
        artifact_path=artifact_text,
        archive_member=member_text,
        source=source,
        identity=identity,
        load_result=load_result,
    )
    _log_scan_metric(
        result,
        elapsed_ns=perf_counter_ns() - started_ns,
        engine_match_invoked=True,
    )
    return result


def yara_scan_with_optional_zip(file_path: object, compiled_rules: object = None) -> YaraScanResult:
    file_text = yara_text(file_path)
    if file_text == "" or not Path(file_text).exists():
        raise FileNotFoundError(yara_message("YARA scan target does not exist: ", file_text))
    if not zipfile.is_zipfile(file_text):
        return yara_scan(file_text, compiled_rules=compiled_rules)
    if compiled_rules is None:
        return _unavailable_result(file_text, "yara_compiled_rules_unavailable", status="unavailable")
    try:
        return scan_yara_zip_archive(
            file_text, compiled_rules=compiled_rules, scan_member=yara_scan,
        )
    except (*SCAN_CONTENT_ERRORS, ValueError) as e:
        return _unavailable_result(
            file_text,
            "yara_zip_scan_failed:" + yara_text(e)[:320],
            status="failed",
        )


__all__ = (
    "normalize_yara_hits", "normalize_yara_rule_name", "yara_expected_behavior",
    "yara_scan", "yara_scan_with_optional_zip",
)
