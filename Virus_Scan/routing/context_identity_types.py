"""Immutable routing context identity records."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import (
    exact_bool_or_none,
    exact_finite_float_or_none,
    exact_text_or_none,
)

_ALLOWED_CONTAINER_ENGINES = frozenset({"renpy", "rpgm", "unity", "media", "other"})
_ALLOWED_ARTIFACT_ENGINES = _ALLOWED_CONTAINER_ENGINES
_ALLOWED_EFFECTIVE_ENGINES = frozenset(
    {
        "renpy",
        "rpgm",
        "unity",
        "media",
        "other",
        "embedded_pe_payload",
        "embedded_zip_payload",
        "unity_dotnet",
        "renpy_bytecode",
        "renpy_source",
        "rpa",
        "rpgm_encrypted_asset",
        "il2cpp_metadata",
        "unity_asset_bundle",
        "unity_serialized_asset",
        "jar",
        "apk",
        "docx_zip",
        "pe",
        "elf",
        "macho",
        "zip",
        "wasm",
        "asar",
        "javascript",
        "python_source",
        "json",
    }
)


def _validation_context(context: object) -> str:
    text = exact_text_or_none(context)
    return text or "engine_context"


def _validation_error(context: object, reason: str) -> ValueError:
    return ValueError(str.__add__(_validation_context(context), str.__add__(": ", reason)))


def _required_text(value: object, *, context: object, field_name: str) -> str:
    text = exact_text_or_none(value)
    if text is None or text == "":
        raise _validation_error(context, str.__add__("invalid ", field_name))
    return text


def _optional_text(value: object, *, context: object, field_name: str) -> str | None:
    if value is None:
        return None
    text = exact_text_or_none(value)
    if text is None:
        raise _validation_error(context, str.__add__("invalid ", field_name))
    return text


def _required_text_tuple(value: object, *, context: object, field_name: str) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise _validation_error(context, str.__add__("invalid ", field_name))
    out: list[str] = []
    for item in value:
        text = exact_text_or_none(item)
        if text is None:
            raise _validation_error(context, str.__add__("invalid ", field_name))
        out.append(text)
    return tuple(out)


def _required_bool(value: object, *, context: object, field_name: str) -> bool:
    flag = exact_bool_or_none(value)
    if flag is None:
        raise _validation_error(context, str.__add__("invalid ", field_name))
    return flag


@dataclass(frozen=True, slots=True)
class EngineContextIdentity:
    container_engine: str
    container_engine_confidence: float
    artifact_engine: str
    artifact_engine_confidence: float
    declared_extension: str
    sniffed_type: str
    sniffed_embedded_types: tuple[str, ...]
    extension_mismatch: bool
    cross_engine_artifact: bool
    engine_mismatch: bool
    effective_analysis_engine: str
    baseline_key: str
    extension_baseline: str
    contextual_baseline: str
    container_extension_baseline: str
    secondary_baseline_keys: tuple[str, ...]
    baseline_lookup_order: tuple[str, ...]
    learning_baseline_key: str | None
    blocked_baseline_keys: tuple[str, ...]
    learning_allowed: bool
    learning_reason: str
    fingerprint_evidence: tuple[str, ...]

    def validate(self, *, context: str = "engine_context") -> None:
        container_engine = _required_text(self.container_engine, context=context, field_name="container engine")
        artifact_engine = _required_text(self.artifact_engine, context=context, field_name="artifact engine")
        effective_analysis_engine = _required_text(
            self.effective_analysis_engine,
            context=context,
            field_name="effective analysis engine",
        )
        if container_engine not in _ALLOWED_CONTAINER_ENGINES:
            raise _validation_error(context, "invalid container engine")
        if artifact_engine not in _ALLOWED_ARTIFACT_ENGINES:
            raise _validation_error(context, "invalid artifact engine")
        if effective_analysis_engine not in _ALLOWED_EFFECTIVE_ENGINES:
            raise _validation_error(context, "invalid effective analysis engine")
        for field_name, value in (
            ("container_engine_confidence", self.container_engine_confidence),
            ("artifact_engine_confidence", self.artifact_engine_confidence),
        ):
            metric = exact_finite_float_or_none(value)
            if metric is None or metric < 0.0 or metric > 1.0:
                raise _validation_error(context, str.__add__("invalid ", field_name))
        baseline_key = _required_text(self.baseline_key, context=context, field_name="baseline key")
        _required_text(self.extension_baseline, context=context, field_name="extension baseline ownership")
        baseline_lookup_order = _required_text_tuple(
            self.baseline_lookup_order,
            context=context,
            field_name="baseline lookup order",
        )
        secondary_baseline_keys = _required_text_tuple(
            self.secondary_baseline_keys,
            context=context,
            field_name="secondary baselines",
        )
        sniffed_embedded_types = _required_text_tuple(
            self.sniffed_embedded_types,
            context=context,
            field_name="sniffed embedded types",
        )
        blocked_baseline_keys = _required_text_tuple(
            self.blocked_baseline_keys,
            context=context,
            field_name="blocked baseline keys",
        )
        engine_mismatch = _required_bool(self.engine_mismatch, context=context, field_name="engine mismatch")
        cross_engine_artifact = _required_bool(self.cross_engine_artifact, context=context, field_name="cross engine artifact")
        learning_allowed = _required_bool(self.learning_allowed, context=context, field_name="learning allowed")
        learning_baseline_key = _optional_text(
            self.learning_baseline_key,
            context=context,
            field_name="learning baseline key",
        )
        if len(baseline_lookup_order) > 0 and baseline_lookup_order[0] != baseline_key:
            raise _validation_error(context, "baseline lookup order must begin with baseline key")
        if baseline_key not in baseline_lookup_order:
            raise _validation_error(context, "baseline key missing from lookup order")
        if engine_mismatch and container_engine == artifact_engine:
            raise _validation_error(context, "impossible engine mismatch state")
        if cross_engine_artifact and not engine_mismatch:
            raise _validation_error(context, "cross-engine artifact must be routed as an engine mismatch")
        if learning_allowed and not learning_baseline_key:
            raise _validation_error(context, "learning allowed without a learning baseline key")
        if learning_allowed and learning_baseline_key in blocked_baseline_keys:
            raise _validation_error(context, "learning baseline is blocked")
        if not learning_allowed and learning_baseline_key:
            raise _validation_error(context, "learning baseline set while learning is blocked")
        if len(sniffed_embedded_types) != len(dict.fromkeys(sniffed_embedded_types)):
            raise _validation_error(context, "duplicate sniffed embedded types violate deterministic ordering")
        if len(secondary_baseline_keys) != len(dict.fromkeys(secondary_baseline_keys)):
            raise _validation_error(context, "duplicate secondary baselines violate deterministic ordering")
        if len(baseline_lookup_order) != len(dict.fromkeys(baseline_lookup_order)):
            raise _validation_error(context, "duplicate baseline lookup entries violate deterministic ordering")

    def as_record_fields(self) -> dict[str, object]:
        return {
            "container_engine": self.container_engine,
            "container_engine_confidence": self.container_engine_confidence,
            "artifact_engine": self.artifact_engine,
            "artifact_engine_confidence": self.artifact_engine_confidence,
            "declared_extension": self.declared_extension,
            "sniffed_type": self.sniffed_type,
            "sniffed_embedded_types": list(self.sniffed_embedded_types),
            "extension_mismatch": self.extension_mismatch,
            "cross_engine_artifact": self.cross_engine_artifact,
            "engine_mismatch": self.engine_mismatch,
            "effective_analysis_engine": self.effective_analysis_engine,
            "baseline_key": self.baseline_key,
            "extension_baseline": self.extension_baseline,
            "contextual_baseline": self.contextual_baseline,
            "container_extension_baseline": self.container_extension_baseline,
            "secondary_baseline_keys": list(self.secondary_baseline_keys),
            "baseline_lookup_order": list(self.baseline_lookup_order),
            "learning_baseline_key": self.learning_baseline_key,
            "blocked_baseline_keys": list(self.blocked_baseline_keys),
            "learning_allowed": self.learning_allowed,
            "learning_reason": self.learning_reason,
            "fingerprint_evidence": list(self.fingerprint_evidence),
        }
