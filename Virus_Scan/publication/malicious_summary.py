"""Canonical combined malicious-findings projection.

This module is an index over already-finalized local and subsystem publication
state.  It does not scan artifacts, reevaluate YARA/Chains/MITRE/Clusters,
combine probabilities, or mutate local/external evidence.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
import io
import json
import math

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.publication.chain_summary import ChainFindingsSummary
from Virus_Scan.publication.cluster_summary import ClusterFindingsSummary
from Virus_Scan.publication.content_identity import exact_content_sha256, final_record_content_sha256
from Virus_Scan.publication.mitre_summary import MitreFindingsSummary
from Virus_Scan.publication.virustotal_summary import VirusTotalFindingsSummary
from Virus_Scan.publication.yara_summary import YaraFindingsSummary

MALICIOUS_FINDING_SUMMARY_ROW_SCHEMA_VERSION = "malicious_finding_summary_row_v1"
MALICIOUS_FINDINGS_SUMMARY_SCHEMA_VERSION = "malicious_findings_summary_v1"
_MAX_TEXT = 4096
_MAX_ROWS = 200_000
_LOCAL_MALICIOUS = frozenset({"malicious", "high", "high_confidence", "suspicious_high"})
_LOCAL_SUSPICIOUS = frozenset({"suspicious", "low_confidence", "high_confidence_suspicious", "medium", "medium_confidence"})


def _mapping_get(mapping: object, key: str, default: object = None) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for candidate, value in items:
        if type(candidate) is str and str.__eq__(candidate, key):
            return value
    return default


def _text(value: object, reason: str, *, allow_blank: bool = False, maximum: int = _MAX_TEXT) -> str:
    return exact_bounded_text(value, reason, maximum=maximum, allow_blank=allow_blank)


def _score(value: object, reason: str) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        raise TypeError(reason)
    number = float(value)
    if not math.isfinite(number) or number < 0.0:
        raise ValueError(reason)
    return number


def _local_verdict(record: object) -> str:
    for key in ("classification", "class", "verdict"):
        value = _mapping_get(record, key)
        if type(value) is str and value:
            return _text(value, "malicious_summary_local_verdict_invalid", maximum=128).strip().lower()
    return "unknown"


def _local_score(record: object) -> float:
    value = _mapping_get(record, "score", 0.0)
    return _score(value, "malicious_summary_local_score_invalid")


def _member_identity(record: object) -> str:
    for key in ("archive_member_identity", "member_identity", "archive_member", "member_path"):
        value = _mapping_get(record, key)
        if type(value) is str and value:
            return _text(value, "malicious_summary_member_identity_invalid", maximum=2048)
    return ""


def _included_local_reason(verdict: str) -> tuple[str, str] | None:
    if verdict in _LOCAL_MALICIOUS:
        return "local_malicious_or_high_confidence", "local_malicious"
    if verdict in _LOCAL_SUSPICIOUS:
        return "local_suspicious_or_low_confidence", "local_suspicious"
    return None


def _state(record_keys: set[str], content_sha256: str, member_identity: str, verdict: str, score: float) -> dict[str, object]:
    return {
        "record_keys": record_keys,
        "content_sha256": content_sha256,
        "member_identity": member_identity,
        "local_verdict": verdict,
        "local_score": score,
        "section": "external_or_context_only",
        "inclusion_reasons": set(),
        "physical_roots": set(),
        "yara_refs": set(),
        "chain_refs": set(),
        "mitre_refs": set(),
        "cluster_refs": set(),
        "vt_refs": set(),
        "authority_classes": set(),
        "unavailable_reasons": set(),
        "vt_status": "unavailable",
        "vt_malicious": 0,
        "vt_suspicious": 0,
        "vt_disagreement": "unavailable",
    }


def _exact_refs(values: set[str]) -> tuple[str, ...]:
    return tuple(sorted(values))


@dataclass(frozen=True, slots=True)
class MaliciousFindingSummaryRow:
    record_keys: tuple[str, ...]
    content_sha256: str
    member_identity: str
    local_verdict: str
    local_score: float
    section: str
    inclusion_reasons: tuple[str, ...]
    physical_evidence_root_ids: tuple[str, ...]
    yara_references: tuple[str, ...]
    chain_references: tuple[str, ...]
    mitre_references: tuple[str, ...]
    cluster_references: tuple[str, ...]
    virustotal_references: tuple[str, ...]
    virustotal_status: str
    virustotal_malicious_count: int
    virustotal_suspicious_count: int
    virustotal_disagreement_state: str
    authority_classes: tuple[str, ...]
    unavailable_reasons: tuple[str, ...]
    combined_score: None = None
    schema_version: str = MALICIOUS_FINDING_SUMMARY_ROW_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not MaliciousFindingSummaryRow:
            raise TypeError("malicious_summary_row_owner_invalid")
        if self.schema_version != MALICIOUS_FINDING_SUMMARY_ROW_SCHEMA_VERSION:
            raise ValueError("malicious_summary_row_schema_invalid")
        exact_content_sha256(self.content_sha256, "malicious_summary_content_sha256_invalid")
        if type(self.record_keys) is not tuple or not self.record_keys or self.record_keys != tuple(sorted(set(self.record_keys))):
            raise ValueError("malicious_summary_record_keys_invalid")
        for key in self.record_keys:
            _text(key, "malicious_summary_record_key_invalid")
        _text(self.member_identity, "malicious_summary_member_identity_invalid", allow_blank=True, maximum=2048)
        _text(self.local_verdict, "malicious_summary_local_verdict_invalid", maximum=128)
        _score(self.local_score, "malicious_summary_local_score_invalid")
        if self.section not in {"local_malicious", "local_suspicious", "external_or_context_only"}:
            raise ValueError("malicious_summary_section_invalid")
        if type(self.inclusion_reasons) is not tuple or not self.inclusion_reasons or self.inclusion_reasons != tuple(sorted(set(self.inclusion_reasons))):
            raise ValueError("malicious_summary_inclusion_reasons_invalid")
        for collection in (
            self.physical_evidence_root_ids, self.yara_references, self.chain_references,
            self.mitre_references, self.cluster_references, self.virustotal_references,
            self.authority_classes, self.unavailable_reasons,
        ):
            if type(collection) is not tuple or collection != tuple(sorted(set(collection))):
                raise ValueError("malicious_summary_reference_collection_invalid")
        _text(self.virustotal_status, "malicious_summary_vt_status_invalid", maximum=128)
        _text(self.virustotal_disagreement_state, "malicious_summary_vt_disagreement_invalid", maximum=128)
        for value in (self.virustotal_malicious_count, self.virustotal_suspicious_count):
            if type(value) is not int or type(value) is bool or value < 0:
                raise ValueError("malicious_summary_vt_count_invalid")
        if self.combined_score is not None:
            raise ValueError("malicious_summary_combined_score_forbidden")

    @property
    def semantic_digest(self) -> str:
        return canonical_json_sha256(self.to_record(include_digest=False))

    def to_record(self, *, include_digest: bool = True) -> dict[str, object]:
        record = {
            "authority_classes": self.authority_classes,
            "chain_references": self.chain_references,
            "cluster_references": self.cluster_references,
            "combined_score": None,
            "content_sha256": self.content_sha256,
            "inclusion_reasons": self.inclusion_reasons,
            "local_score": self.local_score,
            "local_verdict": self.local_verdict,
            "member_identity": self.member_identity,
            "mitre_references": self.mitre_references,
            "physical_evidence_root_ids": self.physical_evidence_root_ids,
            "record_keys": self.record_keys,
            "schema_version": self.schema_version,
            "section": self.section,
            "unavailable_reasons": self.unavailable_reasons,
            "virustotal_disagreement_state": self.virustotal_disagreement_state,
            "virustotal_malicious_count": self.virustotal_malicious_count,
            "virustotal_references": self.virustotal_references,
            "virustotal_status": self.virustotal_status,
            "virustotal_suspicious_count": self.virustotal_suspicious_count,
            "yara_references": self.yara_references,
        }
        if include_digest:
            record["row_semantic_digest"] = self.semantic_digest
        return record


@dataclass(frozen=True, slots=True)
class MaliciousFindingsSummary:
    scan_id: str
    snapshot_semantic_digest: str
    source_record_count: int
    identified_record_count: int
    unique_identity_count: int
    duplicate_alias_count: int
    yara_summary_semantic_digest: str
    chain_summary_semantic_digest: str
    mitre_summary_semantic_digest: str
    cluster_summary_semantic_digest: str
    virustotal_summary_semantic_digest: str
    rows: tuple[MaliciousFindingSummaryRow, ...]
    schema_version: str = MALICIOUS_FINDINGS_SUMMARY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not MaliciousFindingsSummary:
            raise TypeError("malicious_summary_owner_invalid")
        if self.schema_version != MALICIOUS_FINDINGS_SUMMARY_SCHEMA_VERSION:
            raise ValueError("malicious_summary_schema_invalid")
        _text(self.scan_id, "malicious_summary_scan_id_invalid", maximum=256)
        exact_content_sha256(self.snapshot_semantic_digest, "malicious_summary_snapshot_digest_invalid")
        for digest in (
            self.yara_summary_semantic_digest,
            self.chain_summary_semantic_digest,
            self.mitre_summary_semantic_digest,
            self.cluster_summary_semantic_digest,
            self.virustotal_summary_semantic_digest,
        ):
            exact_content_sha256(digest, "malicious_summary_source_digest_invalid")
        for value in (
            self.source_record_count,
            self.identified_record_count,
            self.unique_identity_count,
            self.duplicate_alias_count,
        ):
            if type(value) is not int or type(value) is bool or value < 0:
                raise ValueError("malicious_summary_count_invalid")
        if self.identified_record_count > self.source_record_count:
            raise ValueError("malicious_summary_identified_count_invalid")
        if self.unique_identity_count > self.identified_record_count:
            raise ValueError("malicious_summary_unique_identity_count_invalid")
        if self.duplicate_alias_count != self.identified_record_count - self.unique_identity_count:
            raise ValueError("malicious_summary_duplicate_alias_reconciliation_failed")
        if type(self.rows) is not tuple or len(self.rows) > self.unique_identity_count:
            raise ValueError("malicious_summary_rows_invalid")
        identities: list[tuple[str, str]] = []
        for row in self.rows:
            if type(row) is not MaliciousFindingSummaryRow:
                raise TypeError("malicious_summary_row_owner_invalid")
            identities.append((row.content_sha256, row.member_identity))
        if len(set(identities)) != len(identities):
            raise ValueError("malicious_summary_duplicate_finding_identity")
        if identities != sorted(identities):
            raise ValueError("malicious_summary_row_order_invalid")

    def counts_record(self) -> dict[str, int]:
        return {
            "source_record_count": self.source_record_count,
            "identified_record_count": self.identified_record_count,
            "unique_identity_count": self.unique_identity_count,
            "duplicate_alias_count": self.duplicate_alias_count,
            "finding_count": len(self.rows),
            "local_malicious_count": sum(row.section == "local_malicious" for row in self.rows),
            "local_suspicious_count": sum(row.section == "local_suspicious" for row in self.rows),
            "external_or_context_only_count": sum(row.section == "external_or_context_only" for row in self.rows),
            "yara_included_count": sum("verified_yara_hit" in row.inclusion_reasons for row in self.rows),
            "chain_included_count": sum(any(reason.startswith("chain_") for reason in row.inclusion_reasons) for row in self.rows),
            "mitre_included_count": sum(any(reason.startswith("mitre_") for reason in row.inclusion_reasons) for row in self.rows),
            "cluster_included_count": sum("cluster_context_candidate" in row.inclusion_reasons for row in self.rows),
            "virustotal_positive_count": sum("virustotal_positive" in row.inclusion_reasons for row in self.rows),
            "disagreement_count": sum("virustotal_disagreement" in row.inclusion_reasons for row in self.rows),
        }

    @property
    def semantic_digest(self) -> str:
        return canonical_json_sha256(self.core_record())

    def core_record(self) -> dict[str, object]:
        return {
            "counts": self.counts_record(),
            "projection_policy": {
                "cross_subsystem_index_only": True,
                "report_time_detection": False,
                "report_time_scoring": False,
                "combined_score": None,
                "deduplicate_by_content_and_member_identity": True,
                "unknown_is_negative": False,
                "cluster_authority": "context_only",
                "virustotal_authority": "external_corroboration",
            },
            "rows": tuple(row.to_record() for row in self.rows),
            "scan_id": self.scan_id,
            "schema_version": self.schema_version,
            "snapshot_semantic_digest": self.snapshot_semantic_digest,
            "source_summary_digests": {
                "chain": self.chain_summary_semantic_digest,
                "cluster": self.cluster_summary_semantic_digest,
                "mitre": self.mitre_summary_semantic_digest,
                "virustotal": self.virustotal_summary_semantic_digest,
                "yara": self.yara_summary_semantic_digest,
            },
        }

    def to_record(self) -> dict[str, object]:
        record = self.core_record()
        record["summary_semantic_digest"] = self.semantic_digest
        return record


def _groups_from_local_results(local_results: object) -> tuple[dict[tuple[str, str], dict[str, object]], dict[str, tuple[str, str]], int]:
    items = no_hook_mapping_items(local_results)
    if items is None:
        raise TypeError("malicious_summary_local_results_invalid")
    if len(items) > _MAX_ROWS:
        raise ValueError("malicious_summary_source_row_limit_exceeded")
    groups: dict[tuple[str, str], dict[str, object]] = {}
    record_to_group: dict[str, tuple[str, str]] = {}
    identified = 0
    for raw_key, record in items:
        record_key = _text(raw_key, "malicious_summary_record_key_invalid")
        verdict = _local_verdict(record)
        score = _local_score(record)
        try:
            content_sha256 = final_record_content_sha256(record, "malicious_summary_content_sha256_invalid")
        except (TypeError, ValueError):
            if _included_local_reason(verdict) is not None:
                raise RuntimeError("malicious_summary_included_local_content_identity_missing:" + record_key)
            continue
        member = _member_identity(record)
        group_key = (content_sha256, member)
        current = groups.get(group_key)
        if current is None:
            current = _state({record_key}, content_sha256, member, verdict, score)
            groups[group_key] = current
            local_reason = _included_local_reason(verdict)
            if local_reason is not None:
                reason, section = local_reason
                current["inclusion_reasons"].add(reason)
                current["section"] = section
                current["authority_classes"].add("local_final_verdict")
        else:
            if current["local_verdict"] != verdict or current["local_score"] != score:
                raise RuntimeError("malicious_summary_content_alias_local_semantic_conflict:" + content_sha256)
            current["record_keys"].add(record_key)
        record_to_group[record_key] = group_key
        identified += 1
    return groups, record_to_group, identified


def _target_groups(record_keys: tuple[str, ...], record_to_group: dict[str, tuple[str, str]], reason: str) -> tuple[tuple[str, str], ...]:
    found = {record_to_group[key] for key in record_keys if key in record_to_group}
    if not found:
        raise RuntimeError(reason)
    return tuple(sorted(found))


def _add_yara(groups: dict[tuple[str, str], dict[str, object]], record_to_group: dict[str, tuple[str, str]], summary: YaraFindingsSummary) -> None:
    for row in summary.finding_rows:
        targets = _target_groups(row.record_keys, record_to_group, "malicious_summary_yara_local_identity_missing")
        for target in targets:
            state = groups[target]
            state["yara_refs"].add(row.rule_name + ":" + row.root_observation_id)
            if row.root_observation_id:
                state["physical_roots"].add(row.root_observation_id)
            if row.verified:
                state["inclusion_reasons"].add("verified_yara_hit")
                state["authority_classes"].add("physical_rule_match")


def _add_chain(groups: dict[tuple[str, str], dict[str, object]], record_to_group: dict[str, tuple[str, str]], summary: ChainFindingsSummary) -> None:
    for row in summary.finding_rows:
        targets = _target_groups(row.record_keys, record_to_group, "malicious_summary_chain_local_identity_missing")
        for target in targets:
            state = groups[target]
            state["chain_refs"].add(row.chain_id + ":" + row.decision_status)
            state["physical_roots"].update(row.root_evidence_ids)
            if row.decision_status in {"confirmed", "partial"}:
                state["inclusion_reasons"].add("chain_" + row.decision_status)
                state["authority_classes"].add("canonical_chain_decision_projection")


def _add_mitre(groups: dict[tuple[str, str], dict[str, object]], record_to_group: dict[str, tuple[str, str]], summary: MitreFindingsSummary) -> None:
    for row in summary.finding_rows:
        targets = _target_groups(row.record_keys, record_to_group, "malicious_summary_mitre_local_identity_missing")
        for target in targets:
            state = groups[target]
            state["mitre_refs"].add(row.technique_id + ":" + row.decision_status)
            state["physical_roots"].update(row.root_evidence_ids)
            if row.decision_status in {"candidate", "confirmed"}:
                state["inclusion_reasons"].add("mitre_" + row.decision_status)
                state["authority_classes"].add("attack_artifact_implementation_projection")


def _add_cluster(groups: dict[tuple[str, str], dict[str, object]], record_to_group: dict[str, tuple[str, str]], summary: ClusterFindingsSummary) -> None:
    for row in summary.candidate_rows:
        targets = _target_groups(row.record_keys, record_to_group, "malicious_summary_cluster_local_identity_missing")
        for target in targets:
            state = groups[target]
            state["cluster_refs"].add(row.cluster_id + ":" + row.technique_id + ":rank=" + int.__str__(row.rank))
            state["physical_roots"].update(row.shared_physical_root_ids)
            state["inclusion_reasons"].add("cluster_context_candidate")
            state["authority_classes"].add("context_only")


def _add_virustotal(groups: dict[tuple[str, str], dict[str, object]], record_to_group: dict[str, tuple[str, str]], summary: VirusTotalFindingsSummary) -> None:
    for row in summary.rows:
        target = record_to_group.get(row.artifact_path)
        if target is None:
            raise RuntimeError("malicious_summary_virustotal_local_identity_missing")
        state = groups[target]
        state["vt_refs"].add(row.analysis_id or row.reporting_status)
        state["vt_status"] = row.reporting_status
        state["vt_malicious"] = row.malicious
        state["vt_suspicious"] = row.suspicious
        state["vt_disagreement"] = row.disagreement_state
        if row.malicious > 0 or row.suspicious > 0:
            state["inclusion_reasons"].add("virustotal_positive")
            state["authority_classes"].add("external_corroboration")
        if row.disagreement_state.startswith("local_"):
            state["inclusion_reasons"].add("virustotal_disagreement")
            state["authority_classes"].add("external_corroboration")


def _validate_source_summary_identity(scan_id: str, snapshot_digest: str, summary: object, summary_type: type, reason: str) -> None:
    if type(summary) is not summary_type:
        raise TypeError(reason)
    if summary.scan_id != scan_id or summary.snapshot_semantic_digest != snapshot_digest:
        raise ValueError(reason)


def build_malicious_findings_summary(
    *,
    scan_id: object,
    snapshot_semantic_digest: object,
    local_results: object,
    yara_summary: YaraFindingsSummary,
    chain_summary: ChainFindingsSummary,
    mitre_summary: MitreFindingsSummary,
    cluster_summary: ClusterFindingsSummary,
    virustotal_summary: VirusTotalFindingsSummary,
) -> MaliciousFindingsSummary:
    scan_id_text = _text(scan_id, "malicious_summary_scan_id_invalid", maximum=256)
    snapshot_digest = exact_content_sha256(snapshot_semantic_digest, "malicious_summary_snapshot_digest_invalid")
    for summary, summary_type, reason in (
        (yara_summary, YaraFindingsSummary, "malicious_summary_yara_identity_invalid"),
        (chain_summary, ChainFindingsSummary, "malicious_summary_chain_identity_invalid"),
        (mitre_summary, MitreFindingsSummary, "malicious_summary_mitre_identity_invalid"),
        (cluster_summary, ClusterFindingsSummary, "malicious_summary_cluster_identity_invalid"),
        (virustotal_summary, VirusTotalFindingsSummary, "malicious_summary_virustotal_identity_invalid"),
    ):
        _validate_source_summary_identity(scan_id_text, snapshot_digest, summary, summary_type, reason)
    groups, record_to_group, identified = _groups_from_local_results(local_results)
    _add_yara(groups, record_to_group, yara_summary)
    _add_chain(groups, record_to_group, chain_summary)
    _add_mitre(groups, record_to_group, mitre_summary)
    _add_cluster(groups, record_to_group, cluster_summary)
    _add_virustotal(groups, record_to_group, virustotal_summary)
    rows: list[MaliciousFindingSummaryRow] = []
    for group_key in sorted(groups):
        state = groups[group_key]
        reasons = state["inclusion_reasons"]
        if not reasons:
            continue
        roots = state["physical_roots"]
        unavailable = state["unavailable_reasons"]
        if not roots:
            unavailable.add("physical_evidence_roots_not_published_for_combined_row")
        rows.append(MaliciousFindingSummaryRow(
            record_keys=_exact_refs(state["record_keys"]),
            content_sha256=state["content_sha256"],
            member_identity=state["member_identity"],
            local_verdict=state["local_verdict"],
            local_score=state["local_score"],
            section=state["section"],
            inclusion_reasons=_exact_refs(reasons),
            physical_evidence_root_ids=_exact_refs(roots),
            yara_references=_exact_refs(state["yara_refs"]),
            chain_references=_exact_refs(state["chain_refs"]),
            mitre_references=_exact_refs(state["mitre_refs"]),
            cluster_references=_exact_refs(state["cluster_refs"]),
            virustotal_references=_exact_refs(state["vt_refs"]),
            virustotal_status=state["vt_status"],
            virustotal_malicious_count=state["vt_malicious"],
            virustotal_suspicious_count=state["vt_suspicious"],
            virustotal_disagreement_state=state["vt_disagreement"],
            authority_classes=_exact_refs(state["authority_classes"]),
            unavailable_reasons=_exact_refs(unavailable),
        ))
    source_items = no_hook_mapping_items(local_results)
    source_count = 0 if source_items is None else len(source_items)
    duplicate_alias_count = identified - len(groups)
    return MaliciousFindingsSummary(
        scan_id=scan_id_text,
        snapshot_semantic_digest=snapshot_digest,
        source_record_count=source_count,
        identified_record_count=identified,
        unique_identity_count=len(groups),
        duplicate_alias_count=duplicate_alias_count,
        yara_summary_semantic_digest=yara_summary.semantic_digest,
        chain_summary_semantic_digest=chain_summary.semantic_digest,
        mitre_summary_semantic_digest=mitre_summary.semantic_digest,
        cluster_summary_semantic_digest=cluster_summary.semantic_digest,
        virustotal_summary_semantic_digest=virustotal_summary.semantic_digest,
        rows=tuple(rows),
    )


def malicious_findings_json_bytes(summary: MaliciousFindingsSummary) -> bytes:
    return (json.dumps(summary.to_record(), sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def malicious_findings_markdown_bytes(summary: MaliciousFindingsSummary) -> bytes:
    counts = summary.counts_record()
    lines = [
        "# Combined Malicious Findings",
        "",
        "- This report is a deduplicated cross-subsystem index, not a detector or score owner.",
        "- Unknown/unavailable states are not negative evidence; VirusTotal is external corroboration and Cluster is context-only.",
        "- Combined score: unavailable by design.",
        "- Included identities: " + int.__str__(counts["finding_count"]),
        "- Local malicious / suspicious / external-context only: " + " / ".join((
            int.__str__(counts["local_malicious_count"]),
            int.__str__(counts["local_suspicious_count"]),
            int.__str__(counts["external_or_context_only_count"]),
        )),
        "",
        "| SHA-256 | Member | Local verdict | Local score | Section | Inclusion reasons | Authorities |",
        "|---|---|---|---:|---|---|---|",
    ]
    for row in summary.rows:
        lines.append("| " + " | ".join((
            row.content_sha256,
            row.member_identity.replace("|", "\\|").replace("\n", " "),
            row.local_verdict,
            str(row.local_score),
            row.section,
            ", ".join(row.inclusion_reasons),
            ", ".join(row.authority_classes),
        )) + " |")
    lines.append("")
    return ("\n".join(lines) + "\n").encode("utf-8")


def malicious_findings_csv_bytes(summary: MaliciousFindingsSummary) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow((
        "record_keys", "content_sha256", "member_identity", "local_verdict", "local_score", "section",
        "inclusion_reasons", "physical_evidence_root_ids", "yara_references", "chain_references",
        "mitre_references", "cluster_references", "virustotal_references", "virustotal_status",
        "virustotal_malicious_count", "virustotal_suspicious_count", "virustotal_disagreement_state",
        "authority_classes", "unavailable_reasons", "combined_score", "row_semantic_digest",
    ))
    for row in summary.rows:
        writer.writerow((
            json.dumps(row.record_keys), row.content_sha256, row.member_identity, row.local_verdict, row.local_score,
            row.section, json.dumps(row.inclusion_reasons), json.dumps(row.physical_evidence_root_ids),
            json.dumps(row.yara_references), json.dumps(row.chain_references), json.dumps(row.mitre_references),
            json.dumps(row.cluster_references), json.dumps(row.virustotal_references), row.virustotal_status,
            row.virustotal_malicious_count, row.virustotal_suspicious_count, row.virustotal_disagreement_state,
            json.dumps(row.authority_classes), json.dumps(row.unavailable_reasons), "", row.semantic_digest,
        ))
    return stream.getvalue().encode("utf-8")


def render_malicious_findings_summary(summary: MaliciousFindingsSummary) -> tuple[tuple[str, bytes], ...]:
    if type(summary) is not MaliciousFindingsSummary:
        raise TypeError("malicious_findings_summary_required")
    return (
        ("malicious_findings_summary.json", malicious_findings_json_bytes(summary)),
        ("malicious_findings_summary.md", malicious_findings_markdown_bytes(summary)),
        ("malicious_findings_summary.csv", malicious_findings_csv_bytes(summary)),
    )


__all__ = (
    "MALICIOUS_FINDING_SUMMARY_ROW_SCHEMA_VERSION",
    "MALICIOUS_FINDINGS_SUMMARY_SCHEMA_VERSION",
    "MaliciousFindingSummaryRow",
    "MaliciousFindingsSummary",
    "build_malicious_findings_summary",
    "malicious_findings_csv_bytes",
    "malicious_findings_json_bytes",
    "malicious_findings_markdown_bytes",
    "render_malicious_findings_summary",
)
