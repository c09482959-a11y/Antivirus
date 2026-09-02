"""Root-aware generic YARA context without production probability authority.

The canonical YARA subsystem owns execution and physical match facts.  This
module owns only a deterministic detection-facing presentation of those facts.
It deliberately assigns no calibrated confidence, score, family, ATT&CK
technique, or independent probability authority.
"""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.canonical_json import canonical_json_dumps, canonical_json_sha256
from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.contracts.yara_hits import (
    YaraScanResult,
    canonical_yara_scan_result,
)

GENERIC_YARA_EVIDENCE_CONTEXT_SCHEMA_VERSION = (
    "stage2636_11008_generic_yara_evidence_context_v1"
)
_MAX_CONTEXT_ITEMS = 256


def _sorted_unique_texts(
    value: object,
    *,
    reason: str,
    item_reason: str,
    maximum: int = _MAX_CONTEXT_ITEMS,
) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > maximum:
        raise TypeError(reason)
    items = tuple(
        exact_bounded_text(item, item_reason, maximum=256)
        for item in value
    )
    if items != tuple(sorted(set(items))):
        raise ValueError(reason)
    return items


@dataclass(frozen=True, slots=True)
class GenericYaraEvidenceContext:
    """Immutable physical-root context that can never score independently."""

    scan_status: str
    scan_result_digest: str
    scan_pass_id: str
    physical_target_identity: str
    package_kind: str
    root_observation_ids: tuple[str, ...]
    rule_identity_digests: tuple[str, ...]
    rule_names: tuple[str, ...]
    verified_hit_count: int
    total_match_count: int
    retained_match_count: int
    truncated_match_count: int
    probability_authority: bool
    probability_unavailable_reason: str
    schema_version: str = GENERIC_YARA_EVIDENCE_CONTEXT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not GenericYaraEvidenceContext:
            raise TypeError("generic_yara_context_owner_invalid")
        status = exact_bounded_text(
            self.scan_status, "generic_yara_context_status_invalid", maximum=32
        )
        digest = exact_bounded_text(
            self.scan_result_digest,
            "generic_yara_context_scan_digest_invalid",
            maximum=64,
        )
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("generic_yara_context_scan_digest_invalid")
        scan_pass = exact_bounded_text(
            self.scan_pass_id, "generic_yara_context_scan_pass_invalid", maximum=128
        )
        target = exact_bounded_text(
            self.physical_target_identity,
            "generic_yara_context_target_invalid",
            maximum=4096,
            allow_blank=True,
        )
        package = exact_bounded_text(
            self.package_kind, "generic_yara_context_package_invalid", maximum=32
        )
        roots = _sorted_unique_texts(
            self.root_observation_ids,
            reason="generic_yara_context_roots_invalid",
            item_reason="generic_yara_context_root_invalid",
        )
        if any(not root.startswith("obs_") for root in roots):
            raise ValueError("generic_yara_context_root_invalid")
        identities = _sorted_unique_texts(
            self.rule_identity_digests,
            reason="generic_yara_context_rule_identities_invalid",
            item_reason="generic_yara_context_rule_identity_invalid",
        )
        if any(
            len(item) != 64 or any(ch not in "0123456789abcdef" for ch in item)
            for item in identities
        ):
            raise ValueError("generic_yara_context_rule_identity_invalid")
        names = _sorted_unique_texts(
            self.rule_names,
            reason="generic_yara_context_rule_names_invalid",
            item_reason="generic_yara_context_rule_name_invalid",
        )
        for count, reason in (
            (self.verified_hit_count, "generic_yara_context_verified_count_invalid"),
            (self.total_match_count, "generic_yara_context_total_count_invalid"),
            (self.retained_match_count, "generic_yara_context_retained_count_invalid"),
            (self.truncated_match_count, "generic_yara_context_truncated_count_invalid"),
        ):
            if type(count) is not int or type(count) is bool or count < 0:
                raise TypeError(reason)
        if self.verified_hit_count != len(roots) or len(roots) != len(identities):
            raise ValueError("generic_yara_context_identity_counts_invalid")
        if type(self.probability_authority) is not bool:
            raise TypeError("generic_yara_context_probability_authority_invalid")
        if self.probability_authority:
            raise ValueError("generic_yara_context_probability_authority_forbidden")
        unavailable = exact_bounded_text(
            self.probability_unavailable_reason,
            "generic_yara_context_probability_reason_invalid",
            maximum=512,
        )
        schema = exact_bounded_text(
            self.schema_version, "generic_yara_context_schema_invalid", maximum=128
        )
        object.__setattr__(self, "scan_status", status)
        object.__setattr__(self, "scan_result_digest", digest)
        object.__setattr__(self, "scan_pass_id", scan_pass)
        object.__setattr__(self, "physical_target_identity", target)
        object.__setattr__(self, "package_kind", package)
        object.__setattr__(self, "root_observation_ids", roots)
        object.__setattr__(self, "rule_identity_digests", identities)
        object.__setattr__(self, "rule_names", names)
        object.__setattr__(self, "probability_unavailable_reason", unavailable)
        object.__setattr__(self, "schema_version", schema)

    @property
    def semantic_digest(self) -> str:
        payload = self.to_record()
        return canonical_json_sha256(payload)

    def to_record(self) -> dict[str, object]:
        return {
            "package_kind": self.package_kind,
            "physical_target_identity": self.physical_target_identity,
            "probability_authority": self.probability_authority,
            "probability_unavailable_reason": self.probability_unavailable_reason,
            "retained_match_count": self.retained_match_count,
            "root_observation_ids": self.root_observation_ids,
            "rule_identity_digests": self.rule_identity_digests,
            "rule_names": self.rule_names,
            "scan_pass_id": self.scan_pass_id,
            "scan_result_digest": self.scan_result_digest,
            "scan_status": self.scan_status,
            "schema_version": self.schema_version,
            "total_match_count": self.total_match_count,
            "truncated_match_count": self.truncated_match_count,
            "verified_hit_count": self.verified_hit_count,
        }


def _probability_unavailable_reason(result: YaraScanResult) -> str:
    if not result.complete:
        return result.unavailable_reason or "yara_scan_" + result.status
    if not result.verified:
        return "yara_verified_execution_required"
    if result.status == "complete_no_match":
        return "yara_no_matches"
    return "yara_production_calibration_unavailable"


def generic_yara_evidence_context(scan_result: object) -> GenericYaraEvidenceContext:
    """Project one canonical scan result into non-scoring generic context."""
    result = canonical_yara_scan_result(scan_result)
    verified_hits = tuple(hit for hit in result.hits if hit.verified)
    roots = tuple(sorted({hit.root_observation_id for hit in verified_hits}))
    identity_digests = tuple(sorted({hit.rule_identity.digest for hit in verified_hits}))
    names = tuple(sorted({hit.rule_identity.rule_name for hit in verified_hits}))
    return GenericYaraEvidenceContext(
        scan_status=result.status,
        scan_result_digest=result.semantic_digest,
        scan_pass_id=result.scan_pass_id,
        physical_target_identity=result.physical_target_identity,
        package_kind=result.package_kind,
        root_observation_ids=roots,
        rule_identity_digests=identity_digests,
        rule_names=names,
        verified_hit_count=len(verified_hits),
        total_match_count=result.total_match_count,
        retained_match_count=result.retained_match_count,
        truncated_match_count=result.truncated_match_count,
        probability_authority=False,
        probability_unavailable_reason=_probability_unavailable_reason(result),
    )


def serialize_generic_yara_evidence_context(scan_result: object) -> str:
    """Return the immutable generic context as canonical JSON text."""
    context = (
        scan_result
        if type(scan_result) is GenericYaraEvidenceContext
        else generic_yara_evidence_context(scan_result)
    )
    return canonical_json_dumps(context.to_record())


__all__ = (
    "GENERIC_YARA_EVIDENCE_CONTEXT_SCHEMA_VERSION",
    "GenericYaraEvidenceContext",
    "generic_yara_evidence_context",
    "serialize_generic_yara_evidence_context",
)
