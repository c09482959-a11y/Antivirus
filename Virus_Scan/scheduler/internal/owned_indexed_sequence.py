"""No-hook access to exact scheduler-owned indexed sequences."""
from __future__ import annotations

from dataclasses import dataclass
from types import WrapperDescriptorType



_OWNED_INDEXED_SEQUENCE_ACCEPTED_REASON = ""
_OWNED_INDEXED_SEQUENCE_NOT_ADMITTED = "owned_indexed_sequence_not_admitted"


@dataclass(frozen=True)
class OwnedIndexedSequenceDecision:
    """Replayable owned-indexed-sequence admission decision."""

    is_owned: bool
    rejection_reason: str
    accepted_type: str



def _builtin_indexed_sequence_decision(
    value: object,
    *,
    writable: bool,
) -> OwnedIndexedSequenceDecision | None:
    if type(value) is list:
        return OwnedIndexedSequenceDecision(
            is_owned=True,
            rejection_reason=_OWNED_INDEXED_SEQUENCE_ACCEPTED_REASON,
            accepted_type="builtin_list",
        )
    if not writable and type(value) is tuple:
        return OwnedIndexedSequenceDecision(
            is_owned=True,
            rejection_reason=_OWNED_INDEXED_SEQUENCE_ACCEPTED_REASON,
            accepted_type="builtin_tuple_readonly",
        )
    return None


def _sharedctypes_indexed_sequence_decision(
    value: object,
    *,
    writable: bool,
) -> OwnedIndexedSequenceDecision:
    value_type = type(value)
    try:
        module_name = type.__getattribute__(value_type, "__module__")
        length_descriptor = type.__getattribute__(value_type, "__len__")
        get_descriptor = type.__getattribute__(value_type, "__getitem__")
        set_descriptor = (
            type.__getattribute__(value_type, "__setitem__")
            if writable
            else None
        )
    except (AttributeError, TypeError):
        return OwnedIndexedSequenceDecision(
            is_owned=False,
            rejection_reason="owned_indexed_sequence_type_rejected",
            accepted_type=_OWNED_INDEXED_SEQUENCE_NOT_ADMITTED,
        )
    if module_name != "multiprocessing.sharedctypes":
        return OwnedIndexedSequenceDecision(
            is_owned=False,
            rejection_reason="owned_indexed_sequence_module_rejected",
            accepted_type=_OWNED_INDEXED_SEQUENCE_NOT_ADMITTED,
        )
    if (
        type(length_descriptor) is not WrapperDescriptorType
        or type(get_descriptor) is not WrapperDescriptorType
    ):
        return OwnedIndexedSequenceDecision(
            is_owned=False,
            rejection_reason="owned_indexed_sequence_descriptor_rejected",
            accepted_type=_OWNED_INDEXED_SEQUENCE_NOT_ADMITTED,
        )
    if writable and type(set_descriptor) is not WrapperDescriptorType:
        return OwnedIndexedSequenceDecision(
            is_owned=False,
            rejection_reason="owned_indexed_sequence_set_descriptor_rejected",
            accepted_type=_OWNED_INDEXED_SEQUENCE_NOT_ADMITTED,
        )
    return OwnedIndexedSequenceDecision(
        is_owned=True,
        rejection_reason=_OWNED_INDEXED_SEQUENCE_ACCEPTED_REASON,
        accepted_type="sharedctypes_indexed_sequence",
    )


def owned_indexed_sequence_decision(
    value: object, *, writable: bool
) -> OwnedIndexedSequenceDecision:
    builtin_decision = _builtin_indexed_sequence_decision(value, writable=writable)
    if builtin_decision is not None:
        return builtin_decision
    return _sharedctypes_indexed_sequence_decision(value, writable=writable)

def owned_indexed_set(value: object, index: int, item: object) -> None:
    if type(value) is list:
        list.__setitem__(value, index, item)
        return
    type.__getattribute__(type(value), "__setitem__")(value, index, item)

def owned_indexed_sequence_rejection_reason(value: object, *, writable: bool) -> str:
    return owned_indexed_sequence_decision(value, writable=writable).rejection_reason


def is_owned_indexed_sequence(value: object, *, writable: bool) -> bool:
    return owned_indexed_sequence_decision(value, writable=writable).is_owned


def owned_indexed_length(value: object) -> int:
    if type(value) is list:
        return list.__len__(value)
    if type(value) is tuple:
        return tuple.__len__(value)
    return type.__getattribute__(type(value), "__len__")(value)


def owned_indexed_get(value: object, index: int) -> object:
    if type(value) is list:
        return list.__getitem__(value, index)
    if type(value) is tuple:
        return tuple.__getitem__(value, index)
    return type.__getattribute__(type(value), "__getitem__")(value, index)
__all__ = (
    "OwnedIndexedSequenceDecision",
    "is_owned_indexed_sequence",
    "owned_indexed_get",
    "owned_indexed_length",
    "owned_indexed_sequence_decision",
    "owned_indexed_sequence_rejection_reason",
    "owned_indexed_set",
)
