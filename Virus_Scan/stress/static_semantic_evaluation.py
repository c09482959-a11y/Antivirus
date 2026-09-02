"""Immutable Phase 26 metrics for the inert static-semantic corpus.

The evaluator consumes canonical parser results and independent Phase 25 oracle
records.  It does not construct scanner evidence, Tags, Chains, ATT&CK
techniques, probabilities, or learning mutations.
"""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.numeric_boundaries import (
    exact_bounded_nonnegative_int,
    exact_optional_rate,
)
from Virus_Scan.contracts.text_boundaries import exact_bounded_text

STATIC_SEMANTIC_EVALUATION_SCHEMA_VERSION = (
    "stage2636_11020_static_semantic_evaluation_v1"
)
_MAX_ROWS = 10_000
_MAX_FACTS = 1_000_000


def _texts(value: object, reason: str, *, maximum: int = 4096) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > maximum:
        raise TypeError(reason)
    out = tuple(
        exact_bounded_text(item, reason, maximum=512)
        for item in value
    )
    if out != tuple(sorted(set(out))):
        raise ValueError(reason)
    return out


@dataclass(frozen=True, slots=True)
class StaticSemanticEvaluationRow:
    """One exact oracle-versus-canonical-static-analysis reconciliation row."""

    sample_id: str
    partition: str
    malware_class: str
    generation_id: str
    artifact_sha256: str
    expected_parser_status: str
    observed_parser_status: str
    analysis_available: bool
    unavailable_reason: str
    scanner_id: str
    cache_source: str
    semantic_digest: str
    expected_operation_kinds: tuple[str, ...]
    observed_operation_kinds: tuple[str, ...]
    matched_operation_kinds: tuple[str, ...]
    missing_operation_kinds: tuple[str, ...]
    unexpected_operation_kinds: tuple[str, ...]
    forbidden_operation_kinds_observed: tuple[str, ...]
    reachability_truth_count: int
    reachability_match_count: int
    flow_truth_count: int
    flow_match_count: int
    operation_count: int
    flow_edge_count: int
    route_tag_count: int
    execution_observed: bool = False
    eligible_for_confirmation: bool = False
    eligible_for_probability: bool = False
    schema_version: str = STATIC_SEMANTIC_EVALUATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not StaticSemanticEvaluationRow:
            raise TypeError("static_semantic_evaluation_row_owner_invalid")
        text_fields = (
            ("sample_id", self.sample_id, 128, False),
            ("partition", self.partition, 32, False),
            ("malware_class", self.malware_class, 16, False),
            ("generation_id", self.generation_id, 128, False),
            ("artifact_sha256", self.artifact_sha256, 64, False),
            ("expected_parser_status", self.expected_parser_status, 32, False),
            ("observed_parser_status", self.observed_parser_status, 32, False),
            ("unavailable_reason", self.unavailable_reason, 512, True),
            ("scanner_id", self.scanner_id, 128, True),
            ("cache_source", self.cache_source, 32, False),
            ("semantic_digest", self.semantic_digest, 64, True),
            ("schema_version", self.schema_version, 128, False),
        )
        materialized: dict[str, str] = {}
        for name, value, maximum, blank in text_fields:
            materialized[name] = exact_bounded_text(
                value,
                "static_semantic_evaluation_" + name + "_invalid",
                maximum=maximum,
                allow_blank=blank,
            )
        digest = materialized["artifact_sha256"]
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("static_semantic_evaluation_artifact_sha256_invalid")
        semantic_digest = materialized["semantic_digest"]
        if semantic_digest and (
            len(semantic_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in semantic_digest)
        ):
            raise ValueError("static_semantic_evaluation_semantic_digest_invalid")
        if materialized["schema_version"] != STATIC_SEMANTIC_EVALUATION_SCHEMA_VERSION:
            raise ValueError("static_semantic_evaluation_schema_invalid")
        if materialized["malware_class"] not in {"malware", "control"}:
            raise ValueError("static_semantic_evaluation_malware_class_invalid")
        for name in (
            "analysis_available", "execution_observed",
            "eligible_for_confirmation", "eligible_for_probability",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError("static_semantic_evaluation_boolean_invalid:" + name)
        if self.execution_observed or self.eligible_for_confirmation or self.eligible_for_probability:
            raise ValueError("static_semantic_evaluation_authority_invalid")
        if self.analysis_available and materialized["unavailable_reason"]:
            raise ValueError("static_semantic_evaluation_available_reason_invalid")
        if not self.analysis_available and not materialized["unavailable_reason"]:
            raise ValueError("static_semantic_evaluation_unavailable_reason_missing")
        tuple_fields = (
            "expected_operation_kinds", "observed_operation_kinds",
            "matched_operation_kinds", "missing_operation_kinds",
            "unexpected_operation_kinds", "forbidden_operation_kinds_observed",
        )
        for name in tuple_fields:
            object.__setattr__(self, name, _texts(
                getattr(self, name),
                "static_semantic_evaluation_" + name + "_invalid",
            ))
        for name in (
            "reachability_truth_count", "reachability_match_count",
            "flow_truth_count", "flow_match_count", "operation_count",
            "flow_edge_count", "route_tag_count",
        ):
            object.__setattr__(self, name, exact_bounded_nonnegative_int(
                getattr(self, name),
                "static_semantic_evaluation_" + name + "_invalid",
                maximum=_MAX_FACTS,
            ))
        if self.reachability_match_count > self.reachability_truth_count:
            raise ValueError("static_semantic_evaluation_reachability_count_invalid")
        if self.flow_match_count > self.flow_truth_count:
            raise ValueError("static_semantic_evaluation_flow_count_invalid")
        expected = set(self.expected_operation_kinds)
        observed = set(self.observed_operation_kinds)
        if set(self.matched_operation_kinds) != expected & observed:
            raise ValueError("static_semantic_evaluation_matched_operations_invalid")
        if set(self.missing_operation_kinds) != expected - observed:
            raise ValueError("static_semantic_evaluation_missing_operations_invalid")
        if set(self.unexpected_operation_kinds) != observed - expected:
            raise ValueError("static_semantic_evaluation_unexpected_operations_invalid")
        for name, value in materialized.items():
            object.__setattr__(self, name, value)

    @property
    def parser_matches(self) -> bool:
        return self.expected_parser_status == self.observed_parser_status

    def to_record(self) -> dict[str, object]:
        base = {
            "analysis_available": self.analysis_available,
            "artifact_sha256": self.artifact_sha256,
            "cache_source": self.cache_source,
            "eligible_for_confirmation": self.eligible_for_confirmation,
            "eligible_for_probability": self.eligible_for_probability,
            "execution_observed": self.execution_observed,
            "expected_operation_kinds": self.expected_operation_kinds,
            "expected_parser_status": self.expected_parser_status,
            "flow_edge_count": self.flow_edge_count,
            "flow_match_count": self.flow_match_count,
            "flow_truth_count": self.flow_truth_count,
            "forbidden_operation_kinds_observed": self.forbidden_operation_kinds_observed,
            "malware_class": self.malware_class,
            "matched_operation_kinds": self.matched_operation_kinds,
            "missing_operation_kinds": self.missing_operation_kinds,
            "observed_operation_kinds": self.observed_operation_kinds,
            "observed_parser_status": self.observed_parser_status,
            "operation_count": self.operation_count,
            "parser_matches": self.parser_matches,
            "partition": self.partition,
            "reachability_match_count": self.reachability_match_count,
            "reachability_truth_count": self.reachability_truth_count,
            "route_tag_count": self.route_tag_count,
            "sample_id": self.sample_id,
            "scanner_id": self.scanner_id,
            "schema_version": self.schema_version,
            "semantic_digest": self.semantic_digest,
            "generation_id": self.generation_id,
            "unavailable_reason": self.unavailable_reason,
            "unexpected_operation_kinds": self.unexpected_operation_kinds,
        }
        return {**base, "row_digest": canonical_json_sha256(base)}


@dataclass(frozen=True, slots=True)
class StaticSemanticEvaluationMetrics:
    row_count: int
    analysis_available_count: int
    parser_match_count: int
    expected_operation_kind_count: int
    matched_operation_kind_count: int
    observed_operation_kind_count: int
    unexpected_operation_kind_count: int
    forbidden_operation_violation_count: int
    reachability_truth_count: int
    reachability_match_count: int
    flow_truth_count: int
    flow_match_count: int
    control_forbidden_operation_violation_count: int
    unavailable_count: int
    execution_observed_count: int
    production_authority: bool = False
    schema_version: str = STATIC_SEMANTIC_EVALUATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not StaticSemanticEvaluationMetrics:
            raise TypeError("static_semantic_evaluation_metrics_owner_invalid")
        for name in (
            "row_count", "analysis_available_count", "parser_match_count",
            "expected_operation_kind_count", "matched_operation_kind_count",
            "observed_operation_kind_count", "unexpected_operation_kind_count",
            "forbidden_operation_violation_count", "reachability_truth_count",
            "reachability_match_count", "flow_truth_count", "flow_match_count",
            "control_forbidden_operation_violation_count", "unavailable_count",
            "execution_observed_count",
        ):
            object.__setattr__(self, name, exact_bounded_nonnegative_int(
                getattr(self, name),
                "static_semantic_evaluation_metrics_" + name + "_invalid",
                maximum=_MAX_FACTS,
            ))
        if self.row_count > _MAX_ROWS:
            raise ValueError("static_semantic_evaluation_metrics_rows_invalid")
        if self.analysis_available_count + self.unavailable_count != self.row_count:
            raise ValueError("static_semantic_evaluation_metrics_availability_invalid")
        if self.parser_match_count > self.row_count:
            raise ValueError("static_semantic_evaluation_metrics_parser_invalid")
        if self.matched_operation_kind_count > self.expected_operation_kind_count:
            raise ValueError("static_semantic_evaluation_metrics_operation_invalid")
        if self.reachability_match_count > self.reachability_truth_count:
            raise ValueError("static_semantic_evaluation_metrics_reachability_invalid")
        if self.flow_match_count > self.flow_truth_count:
            raise ValueError("static_semantic_evaluation_metrics_flow_invalid")
        if type(self.production_authority) is not bool or self.production_authority:
            raise ValueError("static_semantic_evaluation_metrics_authority_invalid")
        schema = exact_bounded_text(
            self.schema_version,
            "static_semantic_evaluation_metrics_schema_invalid",
            maximum=128,
        )
        if schema != STATIC_SEMANTIC_EVALUATION_SCHEMA_VERSION:
            raise ValueError("static_semantic_evaluation_metrics_schema_invalid")
        object.__setattr__(self, "schema_version", schema)

    @classmethod
    def from_rows(
        cls, rows: tuple[StaticSemanticEvaluationRow, ...],
    ) -> "StaticSemanticEvaluationMetrics":
        if (
            type(rows) is not tuple
            or len(rows) > _MAX_ROWS
            or any(type(row) is not StaticSemanticEvaluationRow for row in rows)
        ):
            raise TypeError("static_semantic_evaluation_metrics_rows_invalid")
        return cls(
            row_count=len(rows),
            analysis_available_count=sum(row.analysis_available for row in rows),
            parser_match_count=sum(row.parser_matches for row in rows),
            expected_operation_kind_count=sum(
                len(row.expected_operation_kinds) for row in rows if row.analysis_available
            ),
            matched_operation_kind_count=sum(
                len(row.matched_operation_kinds) for row in rows if row.analysis_available
            ),
            observed_operation_kind_count=sum(
                len(row.observed_operation_kinds) for row in rows if row.analysis_available
            ),
            unexpected_operation_kind_count=sum(
                len(row.unexpected_operation_kinds) for row in rows if row.analysis_available
            ),
            forbidden_operation_violation_count=sum(
                len(row.forbidden_operation_kinds_observed) for row in rows
            ),
            reachability_truth_count=sum(
                row.reachability_truth_count for row in rows if row.analysis_available
            ),
            reachability_match_count=sum(
                row.reachability_match_count for row in rows if row.analysis_available
            ),
            flow_truth_count=sum(
                row.flow_truth_count for row in rows if row.analysis_available
            ),
            flow_match_count=sum(
                row.flow_match_count for row in rows if row.analysis_available
            ),
            control_forbidden_operation_violation_count=sum(
                len(row.forbidden_operation_kinds_observed)
                for row in rows if row.malware_class == "control"
            ),
            unavailable_count=sum(not row.analysis_available for row in rows),
            execution_observed_count=sum(row.execution_observed for row in rows),
        )

    def to_record(self) -> dict[str, object]:
        base = {
            "analysis_available_count": self.analysis_available_count,
            "control_forbidden_operation_violation_count": self.control_forbidden_operation_violation_count,
            "execution_observed_count": self.execution_observed_count,
            "expected_operation_kind_count": self.expected_operation_kind_count,
            "flow_accuracy": exact_optional_rate(self.flow_match_count, self.flow_truth_count),
            "flow_match_count": self.flow_match_count,
            "flow_truth_count": self.flow_truth_count,
            "forbidden_operation_violation_count": self.forbidden_operation_violation_count,
            "matched_operation_kind_count": self.matched_operation_kind_count,
            "observed_operation_kind_count": self.observed_operation_kind_count,
            "operation_kind_precision": exact_optional_rate(
                self.matched_operation_kind_count,
                self.matched_operation_kind_count + self.unexpected_operation_kind_count,
            ),
            "operation_kind_recall": exact_optional_rate(
                self.matched_operation_kind_count,
                self.expected_operation_kind_count,
            ),
            "parser_accuracy": exact_optional_rate(self.parser_match_count, self.row_count),
            "parser_match_count": self.parser_match_count,
            "production_authority": self.production_authority,
            "reachability_accuracy": exact_optional_rate(
                self.reachability_match_count, self.reachability_truth_count,
            ),
            "reachability_match_count": self.reachability_match_count,
            "reachability_truth_count": self.reachability_truth_count,
            "row_count": self.row_count,
            "schema_version": self.schema_version,
            "unavailable_count": self.unavailable_count,
            "unexpected_operation_kind_count": self.unexpected_operation_kind_count,
        }
        return {**base, "metrics_digest": canonical_json_sha256(base)}


__all__ = (
    "STATIC_SEMANTIC_EVALUATION_SCHEMA_VERSION",
    "StaticSemanticEvaluationMetrics",
    "StaticSemanticEvaluationRow",
)
