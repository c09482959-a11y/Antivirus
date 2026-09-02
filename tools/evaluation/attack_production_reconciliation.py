"""Strict final-JSON reconciliation for the single ATT&CK corpus evaluator."""
from __future__ import annotations

import json
from pathlib import Path, PosixPath, WindowsPath

from Virus_Scan.cli.exit_codes import completed_scan_final_status
from Virus_Scan.detection.attack.evaluation_contracts import (
    AttackEvaluationCorpusManifest,
    AttackEvaluationSample,
)
from Virus_Scan.detection.attack.evaluation_metrics import (
    AttackProductionEvaluationMetrics,
)
from Virus_Scan.detection.attack.evaluation_outcomes import (
    AttackTechniqueEvaluationOutcome,
)
from Virus_Scan.detection.attack.evaluation_results import (
    AttackProductionEvaluationRow,
)
from Virus_Scan.detection.attack.publication import (
    parse_official_attack_probability_evidence,
)
from Virus_Scan.runtime.api import path_contains_filesystem_alias
from tools.evaluation.attack_production_runtime import (
    AttackProductionRuntimeOutput,
)

_PATH_TYPES = (PosixPath, WindowsPath)
_MAX_OUTPUT_BYTES = 512 * 1024 * 1024


def _reject_constant(_value: str) -> object:
    raise ValueError("attack_production_output_nonfinite")


def _reject_pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in items:
        if type(key) is not str or key in out:
            raise ValueError("attack_production_output_duplicate_key")
        out[key] = value
    return out


def _strict_output(path: Path) -> dict[str, object]:
    if (
        type(path) not in _PATH_TYPES
        or path_contains_filesystem_alias(path)
        or not path.is_file()
    ):
        raise ValueError("attack_production_output_file_invalid")
    size = path.stat().st_size
    if size < 2 or size > _MAX_OUTPUT_BYTES:
        raise ValueError("attack_production_output_size_invalid")
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_pairs,
        parse_constant=_reject_constant,
    )
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise TypeError("attack_production_output_invalid")
    return value


def _plain_record(value: object, reason: str) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise TypeError(reason)
    return value


def _plain_list(value: object, reason: str) -> list[object]:
    if type(value) is not list:
        raise TypeError(reason)
    return value


def _text(value: object, reason: str, *, blank: bool = False) -> str:
    if type(value) is not str or (not value and not blank) or len(value) > 4096:
        raise TypeError(reason)
    return str.__str__(value)


def _integer(value: object, reason: str) -> int:
    if type(value) is not int or type(value) is bool or value < 0 or value > 255:
        raise TypeError(reason)
    return value


def _record_reasons(
    record: dict[str, object],
    fields: tuple[str, ...],
) -> tuple[str, ...]:
    reasons: set[str] = set()
    for field in fields:
        for item in _plain_list(dict.get(record, field), "attack_production_errors_invalid"):
            if type(item) is str:
                reasons.add(_text(item, "attack_production_error_text_invalid"))
            elif type(item) is dict:
                reasons.add(_text(
                    dict.get(item, "reason"),
                    "attack_production_error_reason_invalid",
                ))
            else:
                raise TypeError("attack_production_error_item_invalid")
    return tuple(sorted(reasons))


def _publication(record: dict[str, object]) -> dict[str, object]:
    model_evidence = _plain_record(
        dict.get(record, "model_evidence"),
        "attack_production_model_evidence_invalid",
    )
    raw = _plain_record(
        dict.get(model_evidence, "mitre_evidence"),
        "attack_production_mitre_evidence_invalid",
    )
    encoded = json.dumps(
        raw,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return parse_official_attack_probability_evidence(encoded)


def _decision_index(publication: dict[str, object]) -> dict[str, dict[str, object]]:
    index: dict[str, dict[str, object]] = {}
    for status in ("confirmed", "candidate", "rejected", "unavailable"):
        values = dict.get(publication, status)
        if type(values) not in (list, tuple):
            raise TypeError("attack_production_decisions_invalid")
        for value in values:
            decision = _plain_record(value, "attack_production_decision_invalid")
            technique_id = _text(
                dict.get(decision, "technique_id"),
                "attack_production_decision_technique_invalid",
            )
            if technique_id in index or dict.get(decision, "status") != status:
                raise ValueError("attack_production_decision_identity_invalid")
            index[technique_id] = decision
    return index


def _string_tuple(value: object, reason: str) -> tuple[str, ...]:
    if type(value) not in (list, tuple):
        raise TypeError(reason)
    items = tuple(_text(item, reason) for item in value)
    if items != tuple(sorted(items)) or len(items) != len(set(items)):
        raise ValueError(reason)
    return items


def _outcome(
    sample: AttackEvaluationSample,
    decision_index: dict[str, dict[str, object]],
) -> tuple[AttackTechniqueEvaluationOutcome, ...]:
    outcomes: list[AttackTechniqueEvaluationOutcome] = []
    for expectation in sample.technique_expectations:
        decision = decision_index.get(expectation.technique_id)
        if decision is None:
            raise ValueError("attack_production_decision_missing")
        outcomes.append(AttackTechniqueEvaluationOutcome(
            technique_id=expectation.technique_id,
            expected_state=expectation.expected_state,
            observed_state=dict.get(decision, "status"),
            probability=dict.get(decision, "probability"),
            evidence_completeness=dict.get(decision, "evidence_completeness"),
            claim_scopes=_string_tuple(
                dict.get(decision, "claim_scopes"),
                "attack_production_claim_scopes_invalid",
            ),
            implementation_ids=_string_tuple(
                dict.get(decision, "implementation_ids"),
                "attack_production_implementation_ids_invalid",
            ),
            rejection_reason=dict.get(decision, "rejection_reason"),
            unavailable_reason=dict.get(decision, "unavailable_reason"),
            missing_requirements=_string_tuple(
                dict.get(decision, "missing_requirements"),
                "attack_production_missing_requirements_invalid",
            ),
            unavailable_fields=_string_tuple(
                dict.get(decision, "unavailable_fields"),
                "attack_production_unavailable_fields_invalid",
            ),
        ))
    return tuple(outcomes)


def _row(
    *,
    corpus: AttackEvaluationCorpusManifest,
    runtime: AttackProductionRuntimeOutput,
    sample: AttackEvaluationSample,
    record: dict[str, object],
) -> AttackProductionEvaluationRow:
    if Path(_text(dict.get(record, "path"), "attack_production_path_invalid")).resolve() != Path(
        sample.artifact_path,
    ).resolve():
        raise ValueError("attack_production_record_path_mismatch")
    if dict.get(record, "sha256") != sample.artifact_sha256:
        raise ValueError("attack_production_record_digest_mismatch")
    exit_code = _integer(dict.get(record, "exit_code"), "attack_production_exit_code_invalid")
    final_status = _text(dict.get(record, "final_status"), "attack_production_final_status_invalid")
    if completed_scan_final_status(exit_code) != final_status:
        raise ValueError("attack_production_record_incomplete")
    if dict.get(record, "timed_out", False) is not False:
        raise ValueError("attack_production_record_timed_out")
    if _record_reasons(record, ("errors",)):
        raise ValueError("attack_production_record_failed")
    degraded_reasons = _record_reasons(record, ("errors_warnings",))
    publication = _publication(record)
    if publication["ready"] is not True:
        raise ValueError("attack_production_mitre_not_ready")
    if publication["repository_digest"] != corpus.repository_digest:
        raise ValueError("attack_production_repository_digest_mismatch")
    if publication["dataset_version"] != runtime.bundle_git_blob_sha1:
        raise ValueError("attack_production_dataset_version_mismatch")
    if publication["policy_version"] != corpus.policy_version:
        raise ValueError("attack_production_policy_version_mismatch")
    status = _plain_record(
        dict.get(publication, "repository_status"),
        "attack_production_repository_status_invalid",
    )
    if dict.get(status, "local_sha256") != runtime.bundle_sha256:
        raise ValueError("attack_production_repository_sha256_mismatch")
    return AttackProductionEvaluationRow(
        sample_id=sample.sample_id,
        partition=sample.partition,
        malware_class=sample.malware_class,
        artifact_path=sample.artifact_path,
        artifact_sha256=sample.artifact_sha256,
        runtime_sample_id=dict.get(record, "sample_id"),
        runtime_exit_code=exit_code,
        final_status=final_status,
        classification=dict.get(record, "classification"),
        degraded_reasons=degraded_reasons,
        repository_digest=publication["repository_digest"],
        dataset_version=publication["dataset_version"],
        policy_version=publication["policy_version"],
        outcomes=_outcome(sample, _decision_index(publication)),
    )


def reconcile_production_runtime(
    *,
    corpus: AttackEvaluationCorpusManifest,
    runtime: AttackProductionRuntimeOutput,
) -> tuple[tuple[AttackProductionEvaluationRow, ...], AttackProductionEvaluationMetrics]:
    if type(corpus) is not AttackEvaluationCorpusManifest:
        raise TypeError("attack_production_corpus_invalid")
    if type(runtime) is not AttackProductionRuntimeOutput:
        raise TypeError("attack_production_runtime_output_invalid")
    if completed_scan_final_status(runtime.returncode) is None:
        raise ValueError("attack_production_runtime_error_exit")
    output = _strict_output(runtime.output_path)
    sample_by_path = {
        str(Path(sample.artifact_path).resolve()): sample
        for sample in runtime.selected_samples
    }
    if len(output) != len(sample_by_path):
        raise ValueError("attack_production_record_count_mismatch")
    rows: list[AttackProductionEvaluationRow] = []
    runtime_ids: set[str] = set()
    for key, value in output.items():
        resolved = str(Path(key).resolve())
        sample = sample_by_path.get(resolved)
        if sample is None:
            raise ValueError("attack_production_unexpected_record")
        record = _plain_record(value, "attack_production_record_invalid")
        row = _row(corpus=corpus, runtime=runtime, sample=sample, record=record)
        if row.runtime_sample_id in runtime_ids:
            raise ValueError("attack_production_duplicate_runtime_sample_id")
        runtime_ids.add(row.runtime_sample_id)
        rows.append(row)
    ordered = tuple(sorted(rows, key=lambda row: row.sample_id))
    metrics = AttackProductionEvaluationMetrics.from_rows(
        ordered,
        synthetic_development=corpus.corpus_evidence_class == "synthetic_development",
        production_authority=(
            corpus.corpus_evidence_class == "independent_external"
            and corpus.label_review_status == "independent_adjudicated"
        ),
    )
    return ordered, metrics


__all__ = ("reconcile_production_runtime",)
