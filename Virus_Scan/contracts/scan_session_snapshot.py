"""Immutable semantic identity for one canonical scan-session generation."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from Virus_Scan.contracts.intrastage_execution import IntrastageExecutionPlan
from Virus_Scan.contracts.runtime_platform_identity import (
    RuntimePlatformIdentity,
)
from Virus_Scan.contracts.scan_cache_fingerprint import (
    ScanCacheExecutionIdentity,
    scan_cache_execution_identity_from_record,
)
from Virus_Scan.contracts.text_boundaries import exact_bounded_text

SCAN_SESSION_SNAPSHOT_SCHEMA_VERSION = "scan_session_snapshot_v3"
_SCAN_SESSION_STATES = frozenset({"available", "disabled", "partial", "unavailable"})


def _hex(value: object, reason: str, *, blank: bool = False) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    text = str.__str__(value).lower()
    if blank and text == "":
        return ""
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise ValueError(reason)
    return text


def _json_builtin(value: object) -> object:
    """Return exact deterministic JSON builtins without invoking caller hooks."""
    if type(value) is dict:
        rows: list[tuple[str, object]] = []
        for key, child in dict.items(value):
            if type(key) is not str:
                raise TypeError("scan_session_record_key_invalid")
            rows.append((str.__str__(key), _json_builtin(child)))
        return {key: child for key, child in sorted(rows, key=lambda row: row[0])}
    if type(value) in (list, tuple):
        return [_json_builtin(item) for item in value]
    if type(value) in (str, int, bool) or value is None:
        return value
    if type(value) is float:
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("scan_session_nonfinite_value")
        return value
    raise TypeError("scan_session_record_value_invalid")


def scan_session_generation_id(record: object) -> str:
    """Return the deterministic ID for one exact generation record."""
    if type(record) is not dict:
        raise TypeError("scan_session_generation_record_invalid")
    raw = json.dumps(
        _json_builtin(record),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

_SCAN_SESSION_GENERATION_FIELDS = frozenset({
    "attack_unavailable_reason", "cache_database_generation",
    "cache_database_schema_digest", "cache_schema_version",
    "chain_registry_digest", "chain_registry_version", "concurrency_digest",
    "concurrency_plan",
    "configuration_digest", "detection_registry_digest", "durability_digest",
    "feature_registry_digest", "feature_registry_state", "mitre_root",
    "model_database_generation", "model_database_schema_digest", "model_state",
    "model_state_digest", "output_schema_digest", "parser_reason",
    "runtime_platform",
    "parser_schema_version", "parser_state", "scan_mode",
    "scanner_registry_digest", "scanner_registry_reason",
    "scanner_registry_state", "schema_version", "static_ir_reason",
    "static_ir_schema_version", "static_ir_state", "subsystem_states",
    "tag_taxonomy_digest", "tag_taxonomy_version", "yara_scan_mode",
    "yara_source_path", "yara_unavailable_reason",
})


def scan_session_generation_record(
    fields: object, cache_execution_identity: object,
) -> dict[str, object]:
    """Build the one exact record whose digest owns a session generation."""
    if type(fields) is not dict or set(fields) != _SCAN_SESSION_GENERATION_FIELDS:
        raise ValueError("scan_session_generation_fields_invalid")
    if type(cache_execution_identity) is not ScanCacheExecutionIdentity:
        raise TypeError("scan_session_cache_execution_identity_invalid")
    record = _json_builtin(fields)
    if type(record) is not dict:
        raise TypeError("scan_session_generation_record_invalid")
    record["cache_execution_identity"] = cache_execution_identity.without_session_record()
    return record


@dataclass(frozen=True, slots=True)
class ScanSubsystemState:
    """One optional subsystem's explicit session state."""

    name: str
    state: str
    identity_digest: str
    reason: str = ""

    def __post_init__(self) -> None:
        name = exact_bounded_text(self.name, "scan_session_subsystem_name_invalid", maximum=64)
        state = exact_bounded_text(self.state, "scan_session_subsystem_state_invalid", maximum=32)
        if state not in _SCAN_SESSION_STATES:
            raise ValueError("scan_session_subsystem_state_invalid")
        digest = _hex(
            self.identity_digest,
            "scan_session_subsystem_digest_invalid",
            blank=state in {"disabled", "unavailable"},
        )
        reason = exact_bounded_text(
            self.reason,
            "scan_session_subsystem_reason_invalid",
            maximum=256,
            allow_blank=True,
        )
        if state in {"available", "partial"} and digest == "":
            raise ValueError("scan_session_subsystem_identity_missing")
        if state in {"disabled", "unavailable"} and digest != "":
            raise ValueError("scan_session_subsystem_identity_present")
        if state == "unavailable" and reason == "":
            raise ValueError("scan_session_subsystem_reason_missing")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "identity_digest", digest)
        object.__setattr__(self, "reason", reason)

    def to_record(self) -> dict[str, object]:
        return {
            "identity_digest": self.identity_digest,
            "name": self.name,
            "reason": self.reason,
            "state": self.state,
        }

    @classmethod
    def from_record(cls, record: object) -> "ScanSubsystemState":
        if type(record) is not dict:
            raise TypeError("scan_session_subsystem_record_invalid")
        if set(record) != {"identity_digest", "name", "reason", "state"}:
            raise ValueError("scan_session_subsystem_record_keys_invalid")
        return cls(
            name=record["name"],
            state=record["state"],
            identity_digest=record["identity_digest"],
            reason=record["reason"],
        )


@dataclass(frozen=True, slots=True)
class ScanSessionSnapshot:
    """All immutable identities that define one scan-session generation."""

    generation_id: str
    runtime_platform: RuntimePlatformIdentity
    scan_mode: str
    configuration_digest: str
    yara_source_path: str
    yara_scan_mode: str
    yara_unavailable_reason: str
    mitre_root: str
    attack_unavailable_reason: str
    scanner_registry_state: str
    scanner_registry_digest: str
    scanner_registry_reason: str
    parser_state: str
    parser_schema_version: str
    parser_reason: str
    static_ir_state: str
    static_ir_schema_version: str
    static_ir_reason: str
    tag_taxonomy_version: str
    tag_taxonomy_digest: str
    chain_registry_version: str
    chain_registry_digest: str
    detection_registry_digest: str
    model_state: str
    model_state_digest: str
    model_database_generation: str
    model_database_schema_digest: str
    feature_registry_state: str
    feature_registry_digest: str
    cache_database_generation: str
    cache_database_schema_digest: str
    cache_schema_version: int
    output_schema_digest: str
    concurrency_plan: IntrastageExecutionPlan
    concurrency_digest: str
    durability_digest: str
    subsystem_states: tuple[ScanSubsystemState, ...]
    cache_execution_identity: ScanCacheExecutionIdentity
    schema_version: str = SCAN_SESSION_SNAPSHOT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        generation = _hex(self.generation_id, "scan_session_generation_invalid")
        if type(self.runtime_platform) is not RuntimePlatformIdentity:
            raise TypeError("scan_session_runtime_platform_invalid")
        runtime_platform = self.runtime_platform
        scan_mode = exact_bounded_text(self.scan_mode, "scan_session_mode_invalid", maximum=64)
        configuration = _hex(self.configuration_digest, "scan_session_configuration_digest_invalid")
        yara_source = exact_bounded_text(
            self.yara_source_path,
            "scan_session_yara_source_path_invalid",
            maximum=4096,
            allow_blank=True,
        )
        yara_mode = exact_bounded_text(self.yara_scan_mode, "scan_session_yara_scan_mode_invalid", maximum=32)
        yara_reason = exact_bounded_text(
            self.yara_unavailable_reason,
            "scan_session_yara_reason_invalid",
            maximum=256,
            allow_blank=True,
        )
        mitre_root = exact_bounded_text(self.mitre_root, "scan_session_mitre_root_invalid", maximum=4096)
        attack_reason = exact_bounded_text(
            self.attack_unavailable_reason,
            "scan_session_attack_reason_invalid",
            maximum=256,
            allow_blank=True,
        )
        scanner_state = self._state(self.scanner_registry_state, "scan_session_scanner_registry_state_invalid")
        parser_state = self._state(self.parser_state, "scan_session_parser_state_invalid")
        static_state = self._state(self.static_ir_state, "scan_session_static_ir_state_invalid")
        model_state = self._state(self.model_state, "scan_session_model_state_invalid")
        feature_state = self._state(self.feature_registry_state, "scan_session_feature_registry_state_invalid")
        scanner_digest = _hex(
            self.scanner_registry_digest,
            "scan_session_scanner_registry_digest_invalid",
            blank=scanner_state in {"disabled", "unavailable"},
        )
        scanner_reason = exact_bounded_text(
            self.scanner_registry_reason,
            "scan_session_scanner_registry_reason_invalid",
            maximum=256,
            allow_blank=True,
        )
        parser_version = exact_bounded_text(
            self.parser_schema_version,
            "scan_session_parser_version_invalid",
            maximum=128,
            allow_blank=True,
        )
        parser_reason = exact_bounded_text(
            self.parser_reason,
            "scan_session_parser_reason_invalid",
            maximum=256,
            allow_blank=True,
        )
        static_version = exact_bounded_text(
            self.static_ir_schema_version,
            "scan_session_static_ir_version_invalid",
            maximum=128,
            allow_blank=True,
        )
        static_reason = exact_bounded_text(
            self.static_ir_reason,
            "scan_session_static_ir_reason_invalid",
            maximum=256,
            allow_blank=True,
        )
        self._state_identity_contract(scanner_state, scanner_digest, scanner_reason, "scanner_registry")
        self._version_state_contract(parser_state, parser_version, parser_reason, "parser")
        self._version_state_contract(static_state, static_version, static_reason, "static_ir")
        taxonomy_version = exact_bounded_text(
            self.tag_taxonomy_version,
            "scan_session_tag_taxonomy_version_invalid",
            maximum=128,
        )
        chain_version = exact_bounded_text(
            self.chain_registry_version,
            "scan_session_chain_registry_version_invalid",
            maximum=128,
        )
        taxonomy_digest = _hex(self.tag_taxonomy_digest, "scan_session_tag_taxonomy_digest_invalid")
        chain_digest = _hex(self.chain_registry_digest, "scan_session_chain_registry_digest_invalid")
        detection_digest = _hex(self.detection_registry_digest, "scan_session_detection_registry_digest_invalid")
        model_digest = _hex(
            self.model_state_digest,
            "scan_session_model_state_digest_invalid",
            blank=model_state in {"disabled", "unavailable"},
        )
        model_generation = _hex(
            self.model_database_generation,
            "scan_session_model_database_generation_invalid",
            blank=model_state in {"disabled", "unavailable"},
        )
        model_schema = _hex(
            self.model_database_schema_digest,
            "scan_session_model_database_schema_invalid",
            blank=model_state in {"disabled", "unavailable"},
        )
        if model_state in {"available", "partial"} and not all((model_digest, model_generation, model_schema)):
            raise ValueError("scan_session_model_identity_missing")
        feature_digest = _hex(
            self.feature_registry_digest,
            "scan_session_feature_registry_digest_invalid",
            blank=feature_state in {"disabled", "unavailable"},
        )
        if feature_state in {"available", "partial"} and feature_digest == "":
            raise ValueError("scan_session_feature_registry_identity_missing")
        cache_generation = _hex(self.cache_database_generation, "scan_session_cache_generation_invalid")
        cache_schema = _hex(self.cache_database_schema_digest, "scan_session_cache_schema_digest_invalid")
        if type(self.cache_schema_version) is not int or type(self.cache_schema_version) is bool or self.cache_schema_version <= 0:
            raise ValueError("scan_session_cache_schema_version_invalid")
        output_digest = _hex(self.output_schema_digest, "scan_session_output_schema_digest_invalid")
        if type(self.concurrency_plan) is not IntrastageExecutionPlan:
            raise TypeError("scan_session_concurrency_plan_invalid")
        concurrency_digest = _hex(self.concurrency_digest, "scan_session_concurrency_digest_invalid")
        if self.concurrency_plan.scheduler_mode != scan_mode:
            raise ValueError("scan_session_concurrency_mode_mismatch")
        if self.concurrency_plan.digest != concurrency_digest:
            raise ValueError("scan_session_concurrency_digest_mismatch")
        durability_digest = _hex(self.durability_digest, "scan_session_durability_digest_invalid")
        if type(self.subsystem_states) is not tuple or not all(type(item) is ScanSubsystemState for item in self.subsystem_states):
            raise TypeError("scan_session_subsystem_states_invalid")
        subsystems = tuple(sorted(self.subsystem_states, key=lambda item: item.name))
        if len({item.name for item in subsystems}) != len(subsystems):
            raise ValueError("scan_session_subsystem_duplicate")
        if type(self.cache_execution_identity) is not ScanCacheExecutionIdentity:
            raise TypeError("scan_session_cache_execution_identity_invalid")
        if self.cache_execution_identity.session_generation_id != generation:
            raise ValueError("scan_session_cache_generation_mismatch")
        schema = exact_bounded_text(self.schema_version, "scan_session_schema_invalid", maximum=128)
        if schema != SCAN_SESSION_SNAPSHOT_SCHEMA_VERSION:
            raise ValueError("scan_session_schema_invalid")
        for name, value in (
            ("generation_id", generation), ("runtime_platform", runtime_platform),
            ("scan_mode", scan_mode),
            ("configuration_digest", configuration), ("yara_source_path", yara_source),
            ("yara_scan_mode", yara_mode), ("yara_unavailable_reason", yara_reason),
            ("mitre_root", mitre_root), ("attack_unavailable_reason", attack_reason),
            ("scanner_registry_state", scanner_state), ("scanner_registry_digest", scanner_digest),
            ("scanner_registry_reason", scanner_reason), ("parser_state", parser_state),
            ("parser_schema_version", parser_version), ("parser_reason", parser_reason),
            ("static_ir_state", static_state), ("static_ir_schema_version", static_version),
            ("static_ir_reason", static_reason), ("tag_taxonomy_version", taxonomy_version),
            ("tag_taxonomy_digest", taxonomy_digest), ("chain_registry_version", chain_version),
            ("chain_registry_digest", chain_digest), ("detection_registry_digest", detection_digest),
            ("model_state", model_state), ("model_state_digest", model_digest),
            ("model_database_generation", model_generation),
            ("model_database_schema_digest", model_schema),
            ("feature_registry_state", feature_state), ("feature_registry_digest", feature_digest),
            ("cache_database_generation", cache_generation),
            ("cache_database_schema_digest", cache_schema),
            ("output_schema_digest", output_digest),
            ("concurrency_plan", self.concurrency_plan),
            ("concurrency_digest", concurrency_digest),
            ("durability_digest", durability_digest), ("subsystem_states", subsystems),
            ("schema_version", schema),
        ):
            object.__setattr__(self, name, value)
        if scan_session_generation_id(self.generation_record()) != generation:
            raise ValueError("scan_session_generation_record_mismatch")

    @staticmethod
    def _state(value: object, reason: str) -> str:
        state = exact_bounded_text(value, reason, maximum=32)
        if state not in _SCAN_SESSION_STATES:
            raise ValueError(reason)
        return state

    @staticmethod
    def _state_identity_contract(state: str, digest: str, reason: str, owner: str) -> None:
        if state in {"available", "partial"} and digest == "":
            raise ValueError(f"scan_session_{owner}_identity_missing")
        if state in {"disabled", "unavailable"} and digest != "":
            raise ValueError(f"scan_session_{owner}_identity_present")
        if state == "unavailable" and reason == "":
            raise ValueError(f"scan_session_{owner}_reason_missing")

    @staticmethod
    def _version_state_contract(state: str, version: str, reason: str, owner: str) -> None:
        if state in {"available", "partial"} and version == "":
            raise ValueError(f"scan_session_{owner}_version_missing")
        if state in {"disabled", "unavailable"} and version != "":
            raise ValueError(f"scan_session_{owner}_version_present")
        if state == "unavailable" and reason == "":
            raise ValueError(f"scan_session_{owner}_reason_missing")

    @property
    def cache_eligible(self) -> bool:
        return self.cache_execution_identity.cache_eligible and self.model_state != "unavailable"

    def _generation_fields(self) -> dict[str, object]:
        return {
            "attack_unavailable_reason": self.attack_unavailable_reason,
            "cache_database_generation": self.cache_database_generation,
            "cache_database_schema_digest": self.cache_database_schema_digest,
            "cache_schema_version": self.cache_schema_version,
            "chain_registry_digest": self.chain_registry_digest,
            "chain_registry_version": self.chain_registry_version,
            "concurrency_digest": self.concurrency_digest,
            "concurrency_plan": self.concurrency_plan.to_record(),
            "configuration_digest": self.configuration_digest,
            "detection_registry_digest": self.detection_registry_digest,
            "durability_digest": self.durability_digest,
            "feature_registry_digest": self.feature_registry_digest,
            "feature_registry_state": self.feature_registry_state,
            "mitre_root": self.mitre_root,
            "model_database_generation": self.model_database_generation,
            "model_database_schema_digest": self.model_database_schema_digest,
            "model_state": self.model_state,
            "model_state_digest": self.model_state_digest,
            "output_schema_digest": self.output_schema_digest,
            "runtime_platform": self.runtime_platform.to_record(),
            "parser_reason": self.parser_reason,
            "parser_schema_version": self.parser_schema_version,
            "parser_state": self.parser_state,
            "scan_mode": self.scan_mode,
            "scanner_registry_digest": self.scanner_registry_digest,
            "scanner_registry_reason": self.scanner_registry_reason,
            "scanner_registry_state": self.scanner_registry_state,
            "schema_version": self.schema_version,
            "static_ir_reason": self.static_ir_reason,
            "static_ir_schema_version": self.static_ir_schema_version,
            "static_ir_state": self.static_ir_state,
            "subsystem_states": [item.to_record() for item in self.subsystem_states],
            "tag_taxonomy_digest": self.tag_taxonomy_digest,
            "tag_taxonomy_version": self.tag_taxonomy_version,
            "yara_scan_mode": self.yara_scan_mode,
            "yara_source_path": self.yara_source_path,
            "yara_unavailable_reason": self.yara_unavailable_reason,
        }

    def generation_record(self) -> dict[str, object]:
        """Return the one exact record whose digest is the generation ID."""
        return scan_session_generation_record(
            self._generation_fields(), self.cache_execution_identity,
        )

    def semantic_record(self) -> dict[str, object]:
        """Return the canonical generation record; retained name has no second semantics."""
        return self.generation_record()

    def to_record(self) -> dict[str, object]:
        record = self.generation_record()
        record.update({
            "cache_execution_identity": self.cache_execution_identity.to_record(),
            "generation_id": self.generation_id,
        })
        return record

    def publication_record(self) -> dict[str, object]:
        return {
            "cache_execution_identity_digest": self.cache_execution_identity.digest,
            "configuration_digest": self.configuration_digest,
            "generation_id": self.generation_id,
            "model_state_digest": self.model_state_digest,
            "runtime_platform": self.runtime_platform.to_record(),
            "runtime_platform_digest": self.runtime_platform.digest,
            "scan_mode": self.scan_mode,
            "schema_version": self.schema_version,
        }

    @property
    def digest(self) -> str:
        return scan_session_generation_id(self.to_record())


def scan_session_snapshot_from_record(record: object) -> ScanSessionSnapshot:
    """Reconstruct one exact current-schema snapshot from a process manifest."""
    if type(record) is not dict:
        raise TypeError("scan_session_snapshot_record_invalid")
    expected = {
        "attack_unavailable_reason", "cache_database_generation",
        "cache_database_schema_digest", "cache_execution_identity",
        "cache_schema_version", "chain_registry_digest", "chain_registry_version",
        "concurrency_digest", "concurrency_plan", "configuration_digest", "detection_registry_digest",
        "durability_digest", "feature_registry_digest", "feature_registry_state",
        "generation_id", "mitre_root", "model_database_generation",
        "model_database_schema_digest", "model_state", "model_state_digest",
        "output_schema_digest", "parser_reason", "parser_schema_version", "parser_state",
        "runtime_platform",
        "scan_mode", "scanner_registry_digest", "scanner_registry_reason",
        "scanner_registry_state", "schema_version", "static_ir_reason",
        "static_ir_schema_version", "static_ir_state", "subsystem_states",
        "tag_taxonomy_digest", "tag_taxonomy_version", "yara_scan_mode",
        "yara_source_path", "yara_unavailable_reason",
    }
    if set(record) != expected:
        raise ValueError("scan_session_snapshot_record_keys_invalid")
    subsystem_records = record["subsystem_states"]
    if type(subsystem_records) is not list:
        raise TypeError("scan_session_subsystem_records_invalid")
    identity_record = record["cache_execution_identity"]
    identity = scan_cache_execution_identity_from_record(identity_record)
    return ScanSessionSnapshot(
        generation_id=record["generation_id"],
        runtime_platform=RuntimePlatformIdentity.from_record(record["runtime_platform"]),
        scan_mode=record["scan_mode"],
        configuration_digest=record["configuration_digest"],
        yara_source_path=record["yara_source_path"],
        yara_scan_mode=record["yara_scan_mode"],
        yara_unavailable_reason=record["yara_unavailable_reason"],
        mitre_root=record["mitre_root"],
        attack_unavailable_reason=record["attack_unavailable_reason"],
        scanner_registry_state=record["scanner_registry_state"],
        scanner_registry_digest=record["scanner_registry_digest"],
        scanner_registry_reason=record["scanner_registry_reason"],
        parser_state=record["parser_state"],
        parser_schema_version=record["parser_schema_version"],
        parser_reason=record["parser_reason"],
        static_ir_state=record["static_ir_state"],
        static_ir_schema_version=record["static_ir_schema_version"],
        static_ir_reason=record["static_ir_reason"],
        tag_taxonomy_version=record["tag_taxonomy_version"],
        tag_taxonomy_digest=record["tag_taxonomy_digest"],
        chain_registry_version=record["chain_registry_version"],
        chain_registry_digest=record["chain_registry_digest"],
        detection_registry_digest=record["detection_registry_digest"],
        model_state=record["model_state"],
        model_state_digest=record["model_state_digest"],
        model_database_generation=record["model_database_generation"],
        model_database_schema_digest=record["model_database_schema_digest"],
        feature_registry_state=record["feature_registry_state"],
        feature_registry_digest=record["feature_registry_digest"],
        cache_database_generation=record["cache_database_generation"],
        cache_database_schema_digest=record["cache_database_schema_digest"],
        cache_schema_version=record["cache_schema_version"],
        output_schema_digest=record["output_schema_digest"],
        concurrency_plan=IntrastageExecutionPlan.from_record(record["concurrency_plan"]),
        concurrency_digest=record["concurrency_digest"],
        durability_digest=record["durability_digest"],
        subsystem_states=tuple(ScanSubsystemState.from_record(item) for item in subsystem_records),
        cache_execution_identity=identity,
        schema_version=record["schema_version"],
    )


def attach_scan_session_record(result: object, snapshot: object) -> object:
    """Attach exact session traceability to an owned result mapping."""
    if type(snapshot) is not ScanSessionSnapshot:
        raise TypeError("scan_session_snapshot_required")
    if type(result) is dict:
        result["scan_session"] = snapshot.publication_record()
    return result


__all__ = (
    "SCAN_SESSION_SNAPSHOT_SCHEMA_VERSION",
    "ScanSessionSnapshot",
    "ScanSubsystemState",
    "attach_scan_session_record",
    "scan_session_generation_id",
    "scan_session_generation_record",
    "scan_session_snapshot_from_record",
)
