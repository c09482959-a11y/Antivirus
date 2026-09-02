"""Typed contracts for in-memory raw policy dependency adapters."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, TypeAlias

RawIssueExtra: TypeAlias = dict[str, object] | None
RawDecodedTags: TypeAlias = list[object]
RawDecodeAnchors: TypeAlias = Iterable[str]


class RuntimeValueReader(Protocol):
    def __call__(self, name: str, default: object = ...) -> object: ...


class RawPolicyIssueRecorder(Protocol):
    def __call__(self, where: str, exc: BaseException, *, extra: object = None) -> object: ...


class RawSimpleSuppressionRecorder(Protocol):
    def __call__(self, where: str, exc: BaseException) -> object: ...


class DecodedPayloadTagsFunc(Protocol):
    def __call__(self, strings_blob: str, path: object = None, *, finalize: bool = True) -> object: ...


class ScannerDegradedTagsFunc(Protocol):
    def __call__(self, existing: object = None, *extra: object) -> object: ...
