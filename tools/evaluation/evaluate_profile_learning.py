"""Deterministic evaluation of canonical profile learning and persistence."""
from __future__ import annotations

from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES

import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import perf_counter

from Virus_Scan.contracts.detection_observation import (
    DetectionObservation,
    ObservationSourceLocation,
)
from Virus_Scan.detection.api.tag_evidence_contracts import normalize_tag_evidence
from Virus_Scan.models.profiles.commit import commit_promoted_learning
from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles
from Virus_Scan.models.profiles.contamination import preflight_learning_contamination
from Virus_Scan.models.profiles.context import contextual_profile_learning_policy
from Virus_Scan.models.profiles.learning_decision import (
    build_learning_decision,
    content_sha256_for_path,
)
from Virus_Scan.models.profiles.maturity import profile_maturity_evidence
from Virus_Scan.models.profiles.persistence import load_engine_profile, save_engine_profile
from Virus_Scan.models.profiles.persistence_snapshot import persisted_engine_profile_snapshot
from Virus_Scan.models.profiles.request_contracts import ProfileLearningGateRequest
from Virus_Scan.models.profiles.snapshots import default_engine_profile, default_extension_baseline
from Virus_Scan.models.profiles.staged_store_schema import default_staged_benign_store
from Virus_Scan.models.profiles.transaction_contracts import LearningCommitRequest
from Virus_Scan.models.profiles.vector_anomaly import vector_baseline_anomaly
from Virus_Scan.models.profiles.vector_statistics import (
    default_profile_vector_statistics,
    update_profile_vector_statistics,
)
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.config_state import (
    configure_profile_corruption_policy,
    configure_profiles_dir,
)
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state
from Virus_Scan.storage import sqlite_lifecycle

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_MATCHING_VECTOR = [0.1] * len(PROFILE_RAW_FEATURE_NAMES)


def _physical_tag_evidence(tags: tuple[str, ...], *, sample_id: str):
    observations = tuple(
        DetectionObservation.create(
            tag=tag,
            producer_id="profile_learning_evaluation",
            stage_id="controlled_fixture",
            modality="static_structure",
            artifact_identity="fixture:" + sample_id,
            source_location=ObservationSourceLocation(
                "fixture_event", locator=sample_id, event_id=tag,
            ),
            integrity_status="verified",
            directness="direct",
            confidence=1.0,
        )
        for tag in sorted(set(tags))
    )
    return normalize_tag_evidence(
        observations, source_detector="profile_learning_evaluation",
        source_stage="controlled_fixture",
    )


def _configure(root: Path) -> Path:
    profiles = root / "profiles"
    profiles.mkdir(parents=True, exist_ok=True)
    configure_profiles_dir(str(profiles))
    configure_profile_corruption_policy("hard-fail")
    state = profile_persistence_state()
    state.bind_profiles_dir(str(profiles))
    state.clear_all_profiles()
    state.set_staged_cache(default_staged_benign_store(), dirty=False)
    configure_runtime_cluster_state(RuntimeClusterState())
    ensure_authoritative_engine_profiles()
    return profiles


def _sample(root: Path, relative: str, payload: bytes = b"clean fixture") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


def _commit_three(
    engine: str, sample: Path, *, tag: str, prefix: str,
) -> tuple[dict[str, object], ...]:
    return tuple(
        commit_promoted_learning(
            engine, str(sample), _physical_tag_evidence(
                (tag,), sample_id=f"{prefix}:{index}",
            ), (), 0.0, "", "clean", (), (), (),
            "asset", "runtime", observation_id=f"{prefix}:{index}",
            scan_integrity={"allow_learning": True},
        )
        for index in range(3)
    )


def _sequence_summary(root: Path) -> dict[str, object]:
    _configure(root)
    sample = _sample(root, "game/script.rpy")
    results = _commit_three("renpy", sample, tag="benign_asset", prefix="sequence")
    duplicate = commit_promoted_learning(
        "renpy", str(sample), _physical_tag_evidence(
            ("benign_asset",), sample_id="sequence:2",
        ), (), 0.0, "", "clean", (), (), (), "asset", "runtime",
        observation_id="sequence:2",
        scan_integrity={"allow_learning": True},
    )
    profile = load_engine_profile("renpy")
    baseline = profile["extension_baselines"]["renpy/.rpy"]
    persisted_before = persisted_engine_profile_snapshot(profile, expected_engine="renpy")
    profile_persistence_state().clear_all_profiles()
    persisted_after = persisted_engine_profile_snapshot(
        load_engine_profile("renpy"), expected_engine="renpy",
    )
    transactions = profile["model_state"]["learning_transactions"]
    return {
        "staged_results": [result.get("reason") for result in results],
        "learned_on_promotion": results[-1].get("learned") is True,
        "duplicate_idempotent": duplicate.get("idempotent_replay") is True,
        "files": baseline["files"],
        "trusted_count": baseline["vector_baseline"]["trusted_count"],
        "transaction_count": len(transactions),
        "complete_transaction_count": sum(
            record.get("status") == "complete" for record in transactions.values()
        ),
        "restart_identity": persisted_before == persisted_after,
    }


def _process_sequence_summary(root: Path) -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, "-m", "tools.evaluation.evaluate_profile_learning",
         "--single-sequence", str(root)],
        cwd=_PROJECT_ROOT, check=True, capture_output=True, text=True,
    )
    return json.loads(completed.stdout)


def _maturity_matrix() -> dict[str, object]:
    matrix: dict[str, object] = {}
    for label, support, diversity in (
        ("cold", 0, 0), ("warming", 3, 2), ("mature", 12, 3),
    ):
        baseline = default_profile_vector_statistics()
        for index in range(support):
            baseline = update_profile_vector_statistics(
                baseline, _MATCHING_VECTOR,
                diversity_key=f"vendor:{index % max(1, diversity)}",
            )
        maturity = profile_maturity_evidence(baseline)
        anomaly = vector_baseline_anomaly(baseline, _MATCHING_VECTOR)
        matrix[label] = {
            "actual_maturity": maturity["maturity"],
            "suppression_authority": maturity["suppression_authority"],
            "ready": anomaly.get("ready") is True,
            "anomaly": float(anomaly.get("anomaly", 0.0)),
            "false_positive": float(anomaly.get("anomaly", 0.0)) > 0.5,
        }
    return matrix


def _unsafe_cohort(root: Path) -> dict[str, object]:
    records: list[dict[str, object]] = []
    cases = (
        ("malicious", "malicious", "benign_asset"),
        ("unknown", "unknown", "benign_asset"),
        ("dangerous_anchor", "clean", "process_exec"),
    )
    for index, (name, verdict, tag) in enumerate(cases):
        case_root = root / str(index)
        _configure(case_root)
        sample = _sample(case_root, "game/sample.exe")
        result = commit_promoted_learning(
            "other", str(sample), _physical_tag_evidence(
                (tag,), sample_id=f"unsafe:{name}",
            ), (), 95.0 if verdict == "malicious" else 0.0,
            "", verdict, (), (), (), "asset", "runtime",
            observation_id=f"unsafe:{name}", scan_integrity={"allow_learning": True},
        )
        profile = load_engine_profile("other")
        benign_stat_mutation = any(
            baseline.get("files", 0) > 0
            or baseline.get("vector_baseline", {}).get("trusted_count", 0) > 0
            or bool(baseline.get("tag_evidence", {}).get("records"))
            for baseline in profile["extension_baselines"].values()
        ) or bool(profile["model_state"]["learning_transactions"])
        records.append({
            "cohort": name,
            "learned": result.get("learned") is True,
            "mutated_benign_state": benign_stat_mutation,
            "decision_disposition": result.get("learning_decision", {}).get("disposition"),
            "reason": result.get("reason"),
        })
    contaminated = sum(record["mutated_benign_state"] for record in records)
    return {
        "records": records,
        "malicious_to_benign_contamination_rate": contaminated / len(records),
    }


def _engine_cohort(root: Path) -> tuple[dict[str, object], ...]:
    cases = (
        ("renpy", "game/script.rpy"),
        ("rpgm", "game/Data/Actors.rvdata2"),
        ("unity", "game/Managed/Assembly-CSharp.dll"),
        ("media", "game/image.png"),
        ("other", "game/setup.exe"),
    )
    rows: list[dict[str, object]] = []
    for index, (engine, relative) in enumerate(cases):
        case_root = root / str(index)
        _configure(case_root)
        sample = _sample(case_root, relative)
        results = _commit_three(engine, sample, tag="benign_asset", prefix=f"engine:{engine}")
        profile = load_engine_profile(engine)
        rows.append({
            "engine": engine,
            "learned": results[-1].get("learned") is True,
            "transaction_count": len(profile["model_state"]["learning_transactions"]),
            "baseline_count": len(profile["extension_baselines"]),
        })
    return tuple(rows)


def _drift_cohort(root: Path) -> dict[str, object]:
    _configure(root)
    sample = _sample(root, "game/drift.rpy")
    context_fields = contextual_profile_learning_policy(
        str(sample), trusted_benign=True, degraded=False,
    ).as_record_fields()
    validation = {"contextual_engine_identity": context_fields}
    tags = _physical_tag_evidence(("benign_asset",), sample_id="drift:observation")
    gate = ProfileLearningGateRequest(
        "renpy", str(sample), tags, 0.0, "", "clean", (), (),
        scan_integrity={"allow_learning": True},
    )
    decision = build_learning_decision(
        gate, observation_id="drift:observation", yara_hits=(), behavior_flow=(),
        previous_stage="asset", current_stage="runtime", learning_allowed=True,
        reason="evaluation_authorized", validation=validation,
        gate_version="profile_evaluation_v1",
    )
    request = LearningCommitRequest(
        decision=decision, engine="renpy", file_path=str(sample),
        content_sha256=content_sha256_for_path(sample),
        tag_evidence=tags, yara_hits=(), risk=0.0, strings_blob="",
        verdict="clean", api_calls=(), ordered_events=(), behavior_flow=(),
        previous_stage="asset", current_stage="runtime", validation=validation,
        scan_integrity={"allow_learning": True},
    )
    profile = default_engine_profile("renpy")
    context_key = dict(decision.context_identity)["learning_baseline_key"]
    baseline = default_extension_baseline(context_key)
    statistics = default_profile_vector_statistics()
    for index in range(12):
        statistics = update_profile_vector_statistics(
            statistics, [0.0] * len(PROFILE_RAW_FEATURE_NAMES), diversity_key=f"vendor:{index % 3}",
        )
    baseline["vector_baseline"] = statistics
    profile["extension_baselines"][context_key] = baseline
    plan = preflight_learning_contamination(profile, request, [1.0] * len(PROFILE_RAW_FEATURE_NAMES))
    current = profile["extension_baselines"][context_key]["vector_baseline"]
    return {
        "detected": plan.accepted is False and plan.reason == "profile_drift_quarantined",
        "drift_dimension_count": len(plan.drift_dimensions),
        "trusted_count_unchanged": current["trusted_count"] == statistics["trusted_count"],
        "quarantine_count": current["quarantine_count"],
    }


def _corruption_restart_cohort(root: Path) -> dict[str, object]:
    profiles = _configure(root)
    profile = load_engine_profile("renpy")
    profile["model_state"]["learning_rejections"]["evaluation"] = 1
    save_engine_profile("renpy", profile, force=True)
    profile_persistence_state().clear_all_profiles()
    expected = persisted_engine_profile_snapshot(
        load_engine_profile("renpy"), expected_engine="renpy",
    )
    lifecycle = sqlite_lifecycle()
    rolled_back = False
    try:
        with lifecycle.transaction("model") as connection:
            connection.execute(
                "UPDATE profile_engines SET updated_value=updated_value+1000 "
                "WHERE engine_id='renpy' AND profile_scope='default'"
            )
            raise RuntimeError("evaluation_forced_rollback")
    except RuntimeError as exc:
        rolled_back = str(exc) == "evaluation_forced_rollback"
    profile_persistence_state().clear_all_profiles()
    restored = persisted_engine_profile_snapshot(
        load_engine_profile("renpy"), expected_engine="renpy",
    )
    integrity = lifecycle.integrity_check("model")
    return {
        "transaction_rolled_back": rolled_back,
        "exact_restart_state": restored == expected,
        "integrity_ok": integrity.ok,
        "sqlite_only": (profiles / "model_state.sqlite3").exists() and not tuple(
            profiles.glob("*.json*")
        ),
    }


def evaluate_profile_learning() -> dict[str, object]:
    started = perf_counter()
    with TemporaryDirectory(prefix="profile-learning-evaluation-") as temp:
        try:
            root = Path(temp)
            serial = _sequence_summary(root / "serial")
            process_a = _process_sequence_summary(root / "process-a")
            process_b = _process_sequence_summary(root / "process-b")
            unsafe = _unsafe_cohort(root / "unsafe")
            engines = _engine_cohort(root / "engines")
            maturity = _maturity_matrix()
            drift = _drift_cohort(root / "drift")
            corruption = _corruption_restart_cohort(root / "corruption")
        finally:
            sqlite_lifecycle().close()
    elapsed = perf_counter() - started
    benign_false_positives = sum(row["false_positive"] for row in maturity.values())
    unsafe_suppressed = sum(
        record["learned"] for record in unsafe["records"]
    )
    return {
        "clean_commit_success": serial["learned_on_promotion"],
        "duplicate_learning_rate": 0.0 if serial["files"] == 1 and serial["duplicate_idempotent"] else 1.0,
        "serial_replay_summary": serial,
        "process_equivalence": serial == process_a == process_b,
        "unsafe_cohort": unsafe,
        "malicious_suppression_rate": unsafe_suppressed / len(unsafe["records"]),
        "engine_cohort": engines,
        "engine_success_rate": sum(row["learned"] for row in engines) / len(engines),
        "maturity_matrix": maturity,
        "benign_anomaly_false_positive_rate": benign_false_positives / len(maturity),
        "drift_cohort": drift,
        "corruption_restart_cohort": corruption,
        "runtime_seconds": elapsed,
        "runtime_bound_seconds": 20.0,
        "runtime_within_bound": elapsed <= 20.0,
    }


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) == 2 and args[0] == "--single-sequence":
        print(json.dumps(_sequence_summary(Path(args[1])), sort_keys=True))
        return 0
    if args:
        raise SystemExit("unsupported arguments")
    print(json.dumps(evaluate_profile_learning(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
