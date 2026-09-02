"""Deterministic evaluation of the production canonical chain model."""
from __future__ import annotations

from dataclasses import replace
import json
from time import perf_counter

from Virus_Scan.contracts.detection_observation import DetectionObservation, ObservationSourceLocation
from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.registries.chain_registry import (
    CHAIN_REGISTRY_DIGEST,
    CHAIN_REGISTRY_VERSION,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence


def _timed(
    *names: str,
    target_identity: str = "",
    process_identity: str = "",
    artifact_identity: str = "",
    platform: str = "",
    modality: str = "host_telemetry",
    directness: str = "direct",
    correlation_group: str = "",
) -> tuple[DetectionObservation, ...]:
    """Build deterministic physical runtime/API fixtures for Chain evaluation.

    Plain timeline/API dictionaries are intentionally context-only in production.
    Positive evaluation fixtures therefore originate at the canonical physical
    observation owner and carry their ``obs_*`` provenance into Chain matching.
    """
    events: list[DetectionObservation] = []
    for index, name in enumerate(names):
        timestamp = float(index + 1)
        observation = DetectionObservation.create(
            tag=name.lower(),
            producer_id="evaluation_fixture",
            stage_id="physical_runtime_fixture",
            modality=modality,
            platform=platform,
            target_identity=target_identity,
            artifact_identity=artifact_identity,
            process_identity=process_identity,
            source_location=ObservationSourceLocation(
                "fixture_event",
                event_id=f"runtime:{index}:{name.lower()}",
            ),
            timestamp=timestamp,
            timing_provenance="runtime_timestamp",
            integrity_status="verified",
            directness=directness,
            confidence=1.0,
        )
        events.append(observation)
    return tuple(events)


_POSITIVE_FIXTURES = (
    ("download_execute", "execution.download_execute", _timed("network_download", "process_exec"), ()),
    (
        "injection",
        "execution.virtualallocex_writeprocessmemory_createremotethread",
        _timed(
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            target_identity="process:4242", process_identity="process:4242",
            platform="windows", modality="dynamic_runtime", directness="direct",
        ),
        (),
    ),
    (
        "credential_access",
        "anchor:api_lsass_minidump",
        _timed(
            "OpenProcess lsass_access", "MiniDumpWriteDump",
            target_identity="process:lsass", process_identity="process:scanner",
            platform="windows", modality="host_telemetry", directness="direct",
        ),
        (),
    ),
    ("persistence", "execution.persistence_before_payload", _timed("schtasks_create", "process_exec"), ()),
    ("lolbin", "execution.wmi_process_creation", _timed("wmic.exe", "process call create"), ()),
)

_TAG_FIXTURES = (
    ("defense_evasion", "anchor:shadowcopy_delete", ("shadowcopy_delete",), "confirmed", ()),
    ("ransomware", "anchor:ransomware_or_backup_deletion", ("ransomware_behavior",), "confirmed", ()),
    (
        "pickle",
        "anchor:pickle_execution_anchor",
        (),
        "confirmed",
        _timed(
            "pickle_reduce_opcode",
            "pickle_callable_reference",
            modality="static_structure",
            correlation_group="pickle_execution",
        ),
    ),
    ("exfiltration", "anchor:confirmed_exfiltration_upload", ("exfiltration", "http_upload", "network_exfiltration"), "candidate", ()),
)

_BENIGN_FIXTURES = (
    ("signed_updater", ("signed_binary", "network_download", "file_write")),
    ("ordinary_installer", ("installer_package", "file_write", "registry_read")),
    ("asset_fetch", ("asset_resource_fetch", "reference_url", "file_read")),
)



def _tag_observations(*tags: str, shared_root: bool = False) -> tuple[DetectionObservation, ...]:
    observations: list[DetectionObservation] = []
    root = ""
    for index, tag in enumerate(tags):
        observation = DetectionObservation.create(
            tag=tag,
            producer_id="evaluation_fixture",
            stage_id="fixture",
            modality="static_structure",
            artifact_identity="fixture:" + tag,
            source_location=ObservationSourceLocation(
                "fixture_event", event_id=("shared" if shared_root else int.__str__(index)) + ":" + tag,
            ),
            integrity_status="verified",
            root_observation_id=root if shared_root else "",
        )
        if shared_root and not root:
            root = observation.root_observation_id
        observations.append(observation)
    return tuple(observations)


def _decision(evidence: object, chain_id: str) -> object | None:
    return next(
        (item for item in evidence.decisions if item.candidate.chain_id == chain_id),
        None,
    )


def evaluate_chain_model() -> dict[str, object]:
    started = perf_counter()
    fixture_records: list[dict[str, object]] = []
    expected = 0
    found = 0
    confirmed_expected = 0
    confirmed_found = 0

    for family, chain_id, ordered_events, tags in _POSITIVE_FIXTURES:
        evidence = evaluate_chain_evidence(tags=tags, ordered_events=ordered_events)
        decision = _decision(evidence, chain_id)
        expected += 1
        found += int(decision is not None)
        confirmed_expected += 1
        confirmed_found += int(decision is not None and decision.status == "confirmed")
        fixture_records.append({
            "fixture": family,
            "expected_chain": chain_id,
            "expected_status": "confirmed",
            "actual_status": decision.status if decision is not None else "missing",
            "distinct_root_count": len(decision.candidate.distinct_root_ids) if decision is not None else 0,
        })

    for family, chain_id, tags, expected_status, api_calls in _TAG_FIXTURES:
        if family == "pickle":
            normalized = normalize_tag_evidence(
                api_calls,
                source_detector="evaluation_fixture",
                source_stage="pickle_physical_fixture",
            )
            correlated = TagEvidence.from_records(tuple(
                replace(record, correlation_group="pickle_execution")
                for record in normalized.records
            ))
            evidence = evaluate_chain_evidence(tags=correlated)
        else:
            evidence = evaluate_chain_evidence(tags=_tag_observations(*tags), api_calls=api_calls)
        decision = _decision(evidence, chain_id)
        expected += 1
        found += int(decision is not None)
        confirmed_expected += int(expected_status == "confirmed")
        confirmed_found += int(decision is not None and decision.status == "confirmed")
        fixture_records.append({
            "fixture": family,
            "expected_chain": chain_id,
            "expected_status": expected_status,
            "actual_status": decision.status if decision is not None else "missing",
            "distinct_root_count": len(decision.candidate.distinct_root_ids) if decision is not None else 0,
        })

    benign_confirmed = 0
    benign_scoreable = 0
    benign_records: list[dict[str, object]] = []
    for name, tags in _BENIGN_FIXTURES:
        evidence = evaluate_chain_evidence(tags=_tag_observations(*tags))
        confirmed = len(evidence.confirmed)
        scoreable = len(tuple(item for item in evidence.decisions if item.scoreable))
        benign_confirmed += confirmed
        benign_scoreable += scoreable
        benign_records.append({
            "fixture": name,
            "confirmed_count": confirmed,
            "scoreable_count": scoreable,
        })

    unordered = evaluate_chain_evidence(tags=_tag_observations("network_download", "process_exec"))
    unordered_decision = _decision(unordered, "anchor:download_execute_chain")

    duplicate_bundle = normalize_tag_evidence(_tag_observations("shadowcopy_delete", shared_root=True))
    duplicate = evaluate_chain_evidence(tags=duplicate_bundle)
    multi_root_decisions = tuple(
        item for item in duplicate.decisions
        if len(item.candidate.distinct_root_ids) > 1
    )

    replay_a = evaluate_chain_evidence(
        ordered_events=_timed("network_download", "process_exec"),
    ).to_record()
    replay_b = evaluate_chain_evidence(
        ordered_events=_timed("network_download", "process_exec"),
    ).to_record()

    elapsed = perf_counter() - started
    return {
        "registry_version": CHAIN_REGISTRY_VERSION,
        "registry_digest": CHAIN_REGISTRY_DIGEST,
        "fixture_count": len(fixture_records),
        "fixtures": tuple(fixture_records),
        "positive_detection_recall": found / max(1, expected),
        "confirmed_chain_recall": confirmed_found / max(1, confirmed_expected),
        "confirmed_chain_precision_on_fixture_matrix": 1.0 if confirmed_found == confirmed_expected else 0.0,
        "candidate_partial_conversion_accuracy": 1.0 if all(
            row["actual_status"] == row["expected_status"] for row in fixture_records
        ) else 0.0,
        "unordered_cooccurrence_confirmed_false_positives": int(
            unordered_decision is not None and unordered_decision.status == "confirmed"
        ),
        "unordered_cooccurrence_status": (
            unordered_decision.status if unordered_decision is not None else "missing"
        ),
        "benign_confirmed_false_positives": benign_confirmed,
        "benign_scoreable_false_positives": benign_scoreable,
        "benign_fixtures": tuple(benign_records),
        "duplicate_root_multi_signal_inflation_count": len(multi_root_decisions),
        "deterministic_replay": replay_a == replay_b,
        "maximum_decision_count": max(
            len(evaluate_chain_evidence(tags=_tag_observations(*tags)).decisions)
            for _name, tags in _BENIGN_FIXTURES
        ),
        "decision_bound": 256,
        "runtime_seconds": elapsed,
        "runtime_bound_seconds": 2.0,
        "runtime_within_bound": elapsed <= 2.0,
    }


def main() -> int:
    print(json.dumps(evaluate_chain_model(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
