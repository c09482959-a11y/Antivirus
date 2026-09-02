"""Canonical contextual baseline routing and learning gates."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_text


@dataclass(frozen=True, slots=True)
class BaselineRoute:
    baseline_key: str
    extension_baseline: str
    contextual_baseline: str
    container_extension_baseline: str
    sniffed_type_baseline: str
    generic_extension_baseline: str
    unknown_baseline: str
    baseline_lookup_order: tuple[str, ...]
    secondary_baseline_keys: tuple[str, ...]
    learning_baseline_key: str | None
    blocked_baseline_keys: tuple[str, ...]
    learning_allowed: bool
    learning_reason: str


def _norm_engine(value: object) -> str:
    text, reason = no_hook_text(value, missing_reason="engine_missing", unsupported_reason="engine_rejected")
    text = "other" if reason or text == "" else text.lower().strip()
    return text if text in {"renpy", "rpgm", "unity", "media", "other"} else "other"


def _norm_extension(value: object) -> str:
    text, reason = no_hook_text(value, missing_reason="extension_missing", unsupported_reason="extension_rejected")
    text = "<no_ext>" if reason or text == "" else text.lower().strip()
    if not text:
        return "<no_ext>"
    if text != "<no_ext>" and not text.startswith("."):
        text = str.__add__(".", text)
    return text


def _norm_sniffed(value: object) -> str:
    text, reason = no_hook_text(value, missing_reason="sniffed_type_missing", unsupported_reason="sniffed_type_rejected")
    text = "unknown" if reason or text == "" else text.lower().strip()
    return text or "unknown"


def _norm_embedded_types(value: object) -> tuple[str, ...]:
    items = no_hook_sequence_items(value)
    if value is not None and not items and type(value) not in (tuple, list, set, frozenset):
        return ()
    out = []
    for item in items:
        text, reason = no_hook_text(item, unsupported_reason="embedded_type_rejected")
        if not reason and text:
            out.append(text.lower())
    return tuple(out)


def effective_analysis_engine(artifact_engine: object, sniffed_type: object) -> str:
    artifact = _norm_engine(artifact_engine)
    sniffed = _norm_sniffed(sniffed_type)
    effective = artifact
    if sniffed == "pe" and artifact == "unity":
        effective = "unity_dotnet"
    elif sniffed in {"renpy_bytecode", "renpy_source", "rpa"}:
        effective = sniffed
    elif sniffed == "rpgm_encrypted_asset":
        effective = "rpgm_encrypted_asset"
    elif sniffed in {"png", "jpg", "gif", "webp", "bmp", "ogg", "mp3", "wav"}:
        effective = "media"
    elif sniffed in {"mono_dotnet_assembly", "il2cpp_metadata", "unity_asset_bundle", "unity_serialized_asset"}:
        effective = "unity_dotnet" if sniffed == "mono_dotnet_assembly" else sniffed
    elif sniffed in {"jar", "apk", "docx_zip"}:
        effective = sniffed
    elif sniffed in {"pe", "elf", "macho", "zip", "wasm", "asar", "javascript", "python_source", "json"}:
        effective = sniffed
    return effective


@dataclass(frozen=True, slots=True)
class _BaselineRouteIdentity:
    container: str
    artifact: str
    extension: str
    sniffed: str
    contextual_with_sniff: str
    contextual: str
    extension_baseline: str
    container_extension: str
    generic_extension: str
    unknown_baseline: str
    lookup_order: tuple[str, ...]


def _baseline_route_identity(
    container: str,
    artifact: str,
    extension: str,
    sniffed: str,
) -> _BaselineRouteIdentity:
    contextual_with_sniff = container + "::" + artifact + "::" + extension + "::" + sniffed
    contextual = container + "::" + artifact + "::" + extension
    extension_baseline = artifact + "/" + extension
    container_extension = container + "/" + extension
    generic_extension = extension
    unknown_baseline = "other"
    lookup_order = (
        contextual_with_sniff,
        contextual,
        extension_baseline,
        sniffed,
        container_extension,
        generic_extension,
        unknown_baseline,
    )
    return _BaselineRouteIdentity(
        container=container,
        artifact=artifact,
        extension=extension,
        sniffed=sniffed,
        contextual_with_sniff=contextual_with_sniff,
        contextual=contextual,
        extension_baseline=extension_baseline,
        container_extension=container_extension,
        generic_extension=generic_extension,
        unknown_baseline=unknown_baseline,
        lookup_order=lookup_order,
    )


def _secondary_and_blocked_baselines(
    identity: _BaselineRouteIdentity,
    embedded: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    secondaries = list(identity.lookup_order)
    blocked = [identity.container_extension]
    if identity.generic_extension != identity.extension_baseline:
        blocked.append(identity.generic_extension)
    for embedded_type in embedded:
        embedded_extension = embedded_type + "/" + identity.extension
        embedded_context = "::".join(
            (identity.container, str.__add__("embedded_", embedded_type), identity.extension)
        )
        secondaries.extend((embedded_extension, embedded_context))
        blocked.extend((embedded_extension, embedded_context))
        if identity.container_extension != identity.extension_baseline:
            blocked.append(identity.container_extension)
        if identity.generic_extension != identity.extension_baseline:
            blocked.append(identity.generic_extension)
        if embedded_type == "pe":
            secondaries.append("pe/.exe")
            blocked.append("pe/.exe")
    return (
        tuple(dict.fromkeys(secondaries)),
        tuple(dict.fromkeys(blocked)),
    )


def _learning_state(
    *,
    trusted_benign: bool,
    engine_mismatch: bool,
    extension_mismatch: bool,
    embedded: tuple[str, ...],
    degraded: bool,
) -> tuple[bool, str]:
    allowed = (
        trusted_benign is True
        and engine_mismatch is not True
        and extension_mismatch is not True
        and len(embedded) == 0
        and degraded is not True
    )
    if degraded:
        reason = "degraded or partial scan result cannot be learned"
    elif embedded:
        reason = "polyglot or embedded-payload artifact cannot learn as benign media"
    elif engine_mismatch:
        reason = "cross-engine artifact requires trusted benign allowlist before learning"
    elif extension_mismatch:
        reason = "extension-mismatched artifact cannot learn into generic extension baseline"
    elif not trusted_benign:
        reason = "learning requires trusted benign verdict with complete evidence"
    else:
        reason = "trusted benign complete evidence"
    return allowed, reason


@dataclass(frozen=True, slots=True)
class BaselineRouteRequest:
    """Immutable input for contextual baseline routing."""

    container_engine: object
    artifact_engine: object
    declared_extension: object
    sniffed_type: object
    sniffed_embedded_types: object = ()
    extension_mismatch: bool = False
    engine_mismatch: bool = False
    degraded: bool = False
    trusted_benign: bool = False


def build_baseline_route(request: BaselineRouteRequest) -> BaselineRoute:
    """Build one baseline route through the canonical request owner."""
    container = _norm_engine(request.container_engine)
    artifact = _norm_engine(request.artifact_engine)
    extension = _norm_extension(request.declared_extension)
    sniffed = _norm_sniffed(request.sniffed_type)
    embedded = _norm_embedded_types(request.sniffed_embedded_types)
    identity = _baseline_route_identity(container, artifact, extension, sniffed)
    secondary_keys, blocked_keys = _secondary_and_blocked_baselines(identity, embedded)
    learning_allowed, learning_reason = _learning_state(
        trusted_benign=request.trusted_benign,
        engine_mismatch=request.engine_mismatch,
        extension_mismatch=request.extension_mismatch,
        embedded=embedded,
        degraded=request.degraded,
    )
    return BaselineRoute(
        baseline_key=identity.contextual_with_sniff,
        extension_baseline=identity.extension_baseline,
        contextual_baseline=identity.contextual,
        container_extension_baseline=identity.container_extension,
        sniffed_type_baseline=identity.sniffed,
        generic_extension_baseline=identity.generic_extension,
        unknown_baseline=identity.unknown_baseline,
        baseline_lookup_order=identity.lookup_order,
        secondary_baseline_keys=secondary_keys,
        learning_baseline_key=identity.extension_baseline if learning_allowed else None,
        blocked_baseline_keys=blocked_keys,
        learning_allowed=learning_allowed,
        learning_reason=learning_reason,
    )


