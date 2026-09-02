"""Immutable input and normalization outputs for detection stages."""

from __future__ import annotations

from dataclasses import dataclass, field

from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.contracts.yara_hits import YaraScanResult, canonical_yara_scan_result
from Virus_Scan.detection.models.stage_value_utils import (
    detection_unavailable_value,
    detection_value_or_default,
    frozen_failure_records,
    frozen_tuple_or_empty,
)



def _frozen_yara_evidence(value: object) -> YaraScanResult:
    return canonical_yara_scan_result(value)

def _input_stage_text(value: object, replacement: str, reason: str) -> tuple[str, object | None]:
    if value is None:
        return replacement, None
    if type(value) is str:
        text = str.__str__(value)
        return (text or replacement), None
    return replacement, detection_unavailable_value(reason, value)


def _input_stage_bool(value: object, *, replacement: bool, reason: str) -> tuple[bool, object | None]:
    if value is None:
        return replacement, None
    if type(value) is bool:
        return value, None
    return replacement, detection_unavailable_value(reason, value)


@dataclass(frozen=True)
class RawScanFacts:
    """Raw scanner facts only."""

    path: str
    tags: object
    yara_hits: YaraScanResult
    curr_stage: str | None
    strings_blob: str
    strings_already_enriched: bool
    failure_evidence: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        """Deep-freeze direct constructor values from scanner input handoffs."""
        path, path_failure = _input_stage_text(self.path, "", "raw_scan_path_unavailable")
        strings_blob, strings_failure = _input_stage_text(
            self.strings_blob,
            "",
            "raw_scan_strings_blob_unavailable",
        )
        strings_already_enriched, strings_enriched_failure = _input_stage_bool(
            self.strings_already_enriched,
            replacement=False,
            reason="raw_scan_strings_already_enriched_unavailable",
        )
        failure_evidence = (
            *frozen_tuple_or_empty(self.failure_evidence),
            *(item for item in (path_failure, strings_failure, strings_enriched_failure) if item is not None),
        )
        object.__setattr__(self, "path", path)
        object.__setattr__(
            self,
            "tags",
            self.tags if type(self.tags) is TagEvidence else frozen_tuple_or_empty(self.tags),
        )
        object.__setattr__(self, "yara_hits", _frozen_yara_evidence(self.yara_hits))
        object.__setattr__(self, "strings_blob", strings_blob)
        object.__setattr__(self, "strings_already_enriched", strings_already_enriched)
        object.__setattr__(self, "failure_evidence", frozen_failure_records(failure_evidence))

    @classmethod
    def from_inputs(
        cls,
        *,
        path: str,
        tags: object,
        yara_hits: object,
        curr_stage: str | None,
        strings_blob: str,
        strings_already_enriched: bool,
    ) -> "RawScanFacts":
        return cls(
            path=path,
            tags=tags,
            yara_hits=yara_hits,
            curr_stage=curr_stage,
            strings_blob=detection_value_or_default(strings_blob, ""),
            strings_already_enriched=strings_already_enriched,
        )


@dataclass(frozen=True)
class NormalizedFacts:
    """Normalized primitive facts plus integrity-bearing YARA evidence."""

    path: str
    node: str
    tags: tuple[object, ...]
    yara_hits: tuple[object, ...]
    curr_stage: str
    strings_blob: str
    strings_already_enriched: bool
    yara_evidence: YaraScanResult
    artifact_platform: str = ""
    failure_evidence: tuple[object, ...] = ()
    tag_evidence: TagEvidence = field(default_factory=TagEvidence)

    def __post_init__(self) -> None:
        """Deep-freeze direct constructor values from normalized handoffs."""
        path, path_failure = _input_stage_text(self.path, "", "normalized_path_unavailable")
        node, node_failure = _input_stage_text(self.node, "", "normalized_node_unavailable")
        curr_stage, stage_failure = _input_stage_text(self.curr_stage, "unknown", "normalized_stage_unavailable")
        strings_blob, strings_failure = _input_stage_text(
            self.strings_blob,
            "",
            "normalized_strings_blob_unavailable",
        )
        artifact_platform, platform_failure = _input_stage_text(
            self.artifact_platform, "", "normalized_artifact_platform_unavailable",
        )
        if artifact_platform not in {"", "windows", "linux", "macos"}:
            artifact_platform = ""
            platform_failure = detection_unavailable_value(
                "normalized_artifact_platform_invalid", self.artifact_platform,
            )
        strings_already_enriched, strings_enriched_failure = _input_stage_bool(
            self.strings_already_enriched,
            replacement=False,
            reason="normalized_strings_already_enriched_unavailable",
        )
        failure_evidence = (
            *frozen_tuple_or_empty(self.failure_evidence),
            *(
                item
                for item in (path_failure, node_failure, stage_failure, strings_failure, strings_enriched_failure, platform_failure)
                if item is not None
            ),
        )
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "node", node)
        object.__setattr__(self, "tags", frozen_tuple_or_empty(self.tags))
        object.__setattr__(self, "yara_hits", frozen_tuple_or_empty(self.yara_hits))
        object.__setattr__(self, "curr_stage", curr_stage)
        object.__setattr__(self, "strings_blob", strings_blob)
        object.__setattr__(self, "strings_already_enriched", strings_already_enriched)
        object.__setattr__(self, "yara_evidence", _frozen_yara_evidence(self.yara_evidence))
        object.__setattr__(self, "artifact_platform", artifact_platform)
        object.__setattr__(self, "failure_evidence", frozen_failure_records(failure_evidence))
        object.__setattr__(
            self, "tag_evidence",
            self.tag_evidence if type(self.tag_evidence) is TagEvidence else TagEvidence(),
        )

    @classmethod
    def from_values(
        cls,
        *,
        path: str,
        node: str,
        tags: object,
        yara_hits: object,
        curr_stage: str,
        strings_blob: str,
        strings_already_enriched: bool,
        yara_evidence: object = (),
        failure_evidence: object = (),
        tag_evidence: object = None,
        artifact_platform: object = "",
    ) -> "NormalizedFacts":
        return cls(
            path=path,
            node=node,
            tags=tags,
            yara_hits=yara_hits,
            curr_stage=curr_stage,
            strings_blob=detection_value_or_default(strings_blob, ""),
            strings_already_enriched=strings_already_enriched,
            yara_evidence=yara_evidence,
            failure_evidence=detection_value_or_default(failure_evidence, ()),
            tag_evidence=tag_evidence if type(tag_evidence) is TagEvidence else TagEvidence(),
            artifact_platform=artifact_platform,
        )


__all__ = ("NormalizedFacts", "RawScanFacts")
