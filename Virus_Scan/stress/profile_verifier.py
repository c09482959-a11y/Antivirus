"""Profile snapshots and malicious-only clean-learning invariants."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.stress.corpus_types import StressVerificationIssue, StressVerificationReport
from Virus_Scan.stress.execution_types import ProfileFileSnapshot, ProfileSnapshot
from Virus_Scan.storage import (
    CANDIDATE_DATABASE_FILENAME, MODEL_DATABASE_FILENAME, ModelStateRepository,
    SQLiteLifecycleOwner,
)
from Virus_Scan.storage.candidate_repository import LearningCandidateRepository

_AUTHORIZED_JSON_PROFILE_NAMES = frozenset()
_ENGINE_NAMES = ("media", "other", "renpy", "rpgm", "unity")


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _semantic_digest(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _engine_profile_violations(relative_path: str, value: object) -> tuple[str, ...]:
    if type(value) is not dict:
        return (relative_path + ":profile_root_not_object",)
    violations: list[str] = []
    baselines = dict.get(value, "extension_baselines", {})
    if type(baselines) is dict:
        for extension, baseline in dict.items(baselines):
            if type(baseline) is dict and dict.get(baseline, "files", 0) not in (0, None):
                violations.append(relative_path + ":clean_extension_files:" + str(extension))
            gate = dict.get(baseline, "learning_gate", {}) if type(baseline) is dict else {}
            if type(gate) is dict and dict.get(gate, "accepted", 0) not in (0, None):
                violations.append(relative_path + ":clean_learning_accepted:" + str(extension))
    model_state = dict.get(value, "model_state", {})
    if type(model_state) is dict:
        for key in ("cluster_baselines", "markov_baselines", "temporal_baselines", "vector_baselines"):
            if dict.get(model_state, key) not in ({}, [], (), None):
                violations.append(relative_path + ":clean_model_state:" + key)
    return tuple(violations)


def _staged_benign_violations(relative_path: str, value: object) -> tuple[str, ...]:
    if type(value) is not dict:
        return (relative_path + ":staged_benign_root_not_object",)
    violations: list[str] = []
    for key in ("candidates", "staged_candidates", "pending"):
        if dict.get(value, key) not in ({}, [], (), None):
            violations.append(relative_path + ":malicious_candidate_present:" + key)
    promotions = dict.get(value, "promotions", 0)
    if type(promotions) in (int, float) and type(promotions) is not bool and promotions > 0:
        violations.append(relative_path + ":malicious_promotion_count")
    return tuple(violations)


def _profile_json_violations(relative_path: str, value: object) -> tuple[str, ...]:
    name = Path(relative_path).name
    if name in _AUTHORIZED_JSON_PROFILE_NAMES:
        return ()
    violations = [relative_path + ":unauthorized_live_profile_json"]
    if "benign" in name or "candidate" in name:
        violations.extend(_staged_benign_violations(relative_path, value))
    else:
        violations.extend(_engine_profile_violations(relative_path, value))
    return tuple(violations)


def _runtime_model_violations(relative_path: str, value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if type(value) is not dict:
        return (relative_path + ":runtime_model_root_not_object",)
    violations: list[str] = []
    for key in ("markov_transitions", "global_tag_baseline", "global_tag_pair_baseline", "filetype_baseline"):
        if dict.get(value, key) not in ({}, [], (), None):
            violations.append(relative_path + ":malicious_runtime_learning:" + key)
    temporal = dict.get(value, "temporal_state")
    if type(temporal) is dict and dict.get(temporal, "nodes") not in ({}, None):
        violations.append(relative_path + ":malicious_runtime_learning:temporal_nodes")
    cluster = dict.get(value, "cluster_state")
    if type(cluster) is dict:
        for key in ("microclusters", "node_cluster_map", "node_feature_vectors"):
            if dict.get(cluster, key) not in ({}, None):
                violations.append(relative_path + ":malicious_runtime_learning:cluster_" + key)
    learning = dict.get(value, "learning_applied_keys")
    if type(learning) is dict:
        for domain, keys in dict.items(learning):
            if keys not in ([], (), None):
                violations.append(relative_path + ":malicious_runtime_learning_key:" + str(domain))
    return tuple(violations)


def _authoritative_database_violations(root: Path) -> tuple[str, ...]:
    database_path = root / MODEL_DATABASE_FILENAME
    if not database_path.exists():
        return ()
    lifecycle = SQLiteLifecycleOwner()
    lifecycle.configure(root)
    repository = ModelStateRepository(lifecycle)
    violations: list[str] = []
    try:
        integrity = lifecycle.integrity_check("model")
        if integrity.ok is not True:
            violations.append(MODEL_DATABASE_FILENAME + ":integrity_failed")
        for engine in _ENGINE_NAMES:
            profile = repository.read_profile(engine)
            if profile is not None:
                violations.extend(_engine_profile_violations(
                    MODEL_DATABASE_FILENAME + ":profile:" + engine, profile,
                ))
        violations.extend(_runtime_model_violations(
            MODEL_DATABASE_FILENAME + ":runtime", repository.read_runtime_snapshot(),
        ))
    finally:
        lifecycle.close()
    return tuple(violations)


def _candidate_database_violations(root: Path) -> tuple[str, ...]:
    database_path = root / CANDIDATE_DATABASE_FILENAME
    if not database_path.exists():
        return ()
    lifecycle = SQLiteLifecycleOwner()
    lifecycle.configure(root)
    repository = LearningCandidateRepository(lifecycle)
    violations: list[str] = []
    try:
        integrity = lifecycle.integrity_check("candidate")
        if integrity.ok is not True:
            violations.append(CANDIDATE_DATABASE_FILENAME + ":integrity_failed")
        staged = repository.read_staged_store()
        if staged is not None:
            violations.extend(_staged_benign_violations(
                CANDIDATE_DATABASE_FILENAME + ":staged", staged,
            ))
    finally:
        lifecycle.close()
    return tuple(violations)


def snapshot_profiles(root: object) -> ProfileSnapshot:
    path = Path(root).resolve()
    path.mkdir(parents=True, exist_ok=True)
    files: list[ProfileFileSnapshot] = []
    violations: list[str] = list(_authoritative_database_violations(path))
    violations.extend(_candidate_database_violations(path))
    for item in sorted(path.rglob("*"), key=lambda value: value.as_posix().casefold()):
        if not item.is_file():
            continue
        relative = item.relative_to(path).as_posix()
        raw = item.read_bytes()
        json_valid = False
        semantic_digest: str | None = None
        if item.suffix.lower() == ".json" or ".json." in item.name:
            try:
                value = json.loads(raw.decode("utf-8"))
                json_valid = True
                semantic_digest = _semantic_digest(value)
                violations.extend(_profile_json_violations(relative, value))
            except (UnicodeDecodeError, json.JSONDecodeError):
                violations.append(relative + ":malformed_profile_json")
        if item.suffix.lower() in {".tmp", ".partial", ".lock"}:
            violations.append(relative + ":leftover_runtime_artifact")
        files.append(ProfileFileSnapshot(relative, len(raw), hashlib.sha256(raw).hexdigest(), json_valid, semantic_digest))
    return ProfileSnapshot(str(path), tuple(files), tuple(sorted(violations)))


def profile_snapshot_digest(snapshot: ProfileSnapshot) -> str:
    records = tuple({
        "relative_path": item.relative_path,
        "size_bytes": item.size_bytes,
        "sha256": item.sha256,
        "json_valid": item.json_valid,
        "semantic_digest": item.semantic_digest,
    } for item in snapshot.files)
    return hashlib.sha256(_canonical_json_bytes(records)).hexdigest()


def _manifest_identifiers(manifest_path: object) -> tuple[tuple[str, str], ...]:
    try:
        data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except TELEMETRY_FAILURE_ERRORS:
        return ()
    cases = dict.get(data, "cases") if type(data) is dict else None
    if type(cases) is not list:
        return ()
    return tuple((str(dict.get(case, "sample_id", "")), str(dict.get(case, "sha256", ""))) for case in cases if type(case) is dict)


def verify_no_malicious_profile_learning(profiles_dir: object, manifest_path: object) -> StressVerificationReport:
    snapshot = snapshot_profiles(profiles_dir)
    issues = [StressVerificationIssue("profiles", "", "profile_invariant_violation", item) for item in snapshot.violations]
    profile_payloads = tuple(
        (item.relative_path, (Path(snapshot.root) / item.relative_path).read_bytes())
        for item in snapshot.files
    )
    identifiers = _manifest_identifiers(manifest_path)
    for sample_id, sha256 in identifiers:
        sample_bytes = sample_id.encode("utf-8") if sample_id else b""
        sha_bytes = sha256.encode("ascii") if sha256 else b""
        for artifact, payload in profile_payloads:
            if sample_bytes and sample_bytes in payload:
                issues.append(StressVerificationIssue(artifact, sample_id, "malicious_sample_id_learned", sample_id))
            if sha_bytes and sha_bytes in payload:
                issues.append(StressVerificationIssue(artifact, sample_id, "malicious_sha256_learned", sha256))
    return StressVerificationReport(not issues, len(identifiers), tuple(issues))


__all__ = (
    "profile_snapshot_digest",
    "snapshot_profiles",
    "verify_no_malicious_profile_learning",
)
