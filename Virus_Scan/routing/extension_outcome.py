from dataclasses import dataclass
from collections.abc import Iterable, Mapping
from typing import NoReturn

from Virus_Scan.contracts.no_hook_materialization import exact_bool_or_none, no_hook_mapping_items, no_hook_sequence_items, no_hook_text
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.contracts.static_program_analysis import StaticProgramAnalysis


class _ImmutableIdentityDict(dict):
    """Dict-compatible immutable route identity for mapping consumers."""

    def __readonly(self, *_args: object, **_kwargs: object) -> NoReturn:
        exception_message = "route identity is immutable"
        raise TypeError(exception_message)

    def __setitem__(self, key: object, value: object) -> NoReturn:
        self.__readonly(key, value)

    def __delitem__(self, key: object) -> NoReturn:
        self.__readonly(key)

    def clear(self) -> NoReturn:
        self.__readonly()

    def pop(self, key: object, default: object = None) -> NoReturn:
        self.__readonly(key, default)

    def popitem(self) -> NoReturn:
        self.__readonly()

    def setdefault(self, key: object, default: object = None) -> NoReturn:
        self.__readonly(key, default)

    def update(self, *args: object, **kwargs: object) -> NoReturn:
        self.__readonly(*args, **kwargs)


def _freeze_route_identity_value(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is not None:
        out = {}
        for index, (key, item) in enumerate(items):
            key_text, reason = no_hook_text(
                key,
                missing_reason="route_identity_key_missing",
                unsupported_reason="route_identity_key_rejected",
            )
            if reason or key_text == "":
                key_text = "route_identity_key_" + int.__str__(index)
            out[key_text] = _freeze_route_identity_value(item)
        return _ImmutableIdentityDict(out)
    if type(value) in (list, tuple, set, frozenset):
        return tuple(_freeze_route_identity_value(item) for item in value)
    return value


def _detach_route_identity_value(value: object) -> object:
    """Recursively detach canonical identity containers without invoking hooks."""
    if type(value) in (_ImmutableIdentityDict, dict):
        return {
            key: _detach_route_identity_value(item)
            for key, item in dict.items(value)
        }
    if type(value) is tuple:
        return tuple(_detach_route_identity_value(item) for item in value)
    if type(value) is list:
        return [_detach_route_identity_value(item) for item in value]
    return value


def route_identity_record(value: object) -> dict[str, object] | None:
    """Return a recursively detached exact canonical route-identity record."""
    if type(value) in (_ImmutableIdentityDict, dict):
        detached = _detach_route_identity_value(value)
        return detached if type(detached) is dict else None
    items = no_hook_mapping_items(value)
    if items is None:
        return None
    return {key: _detach_route_identity_value(item) for key, item in items}


def _route_tag_text(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="route_tag_missing",
        unsupported_reason="route_tag_rejected",
    )
    return "" if reason else text


def _freeze_route_identity_mapping(value: object) -> _ImmutableIdentityDict:
    if no_hook_mapping_items(value) is None:
        return _ImmutableIdentityDict({})
    frozen = _freeze_route_identity_value(value)
    return frozen if type(frozen) is _ImmutableIdentityDict else _ImmutableIdentityDict({})


@dataclass(frozen=True, slots=True)
class RouteScanOutcome:
    tags: Iterable[object]
    suspicious: object
    identity: Mapping[str, object] | object
    tag_evidence: TagEvidence = TagEvidence()
    static_program_analyses: tuple[StaticProgramAnalysis, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "tags", tuple(tag for tag in (_route_tag_text(item) for item in no_hook_sequence_items(self.tags)) if tag))
        suspicious = exact_bool_or_none(self.suspicious)
        object.__setattr__(self, "suspicious", False if suspicious is None else suspicious)
        object.__setattr__(self, "identity", _freeze_route_identity_mapping(self.identity))
        object.__setattr__(
            self,
            "tag_evidence",
            self.tag_evidence if type(self.tag_evidence) is TagEvidence else TagEvidence(),
        )
        if type(self.static_program_analyses) is not tuple:
            raise TypeError("route_static_program_analyses_invalid")
        if any(type(item) is not StaticProgramAnalysis for item in self.static_program_analyses):
            raise TypeError("route_static_program_analysis_owner_invalid")
        analyses = tuple(sorted(self.static_program_analyses, key=lambda item: item.semantic_digest))
        if len({item.semantic_digest for item in analyses}) != len(analyses):
            raise ValueError("route_static_program_analysis_duplicate")
        object.__setattr__(self, "static_program_analyses", analyses)

    def __iter__(self) -> None:
        yield list(self.tags)
        yield self.suspicious


__all__ = ("RouteScanOutcome", "route_identity_record")
