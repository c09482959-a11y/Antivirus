"""Stage 1669: detection/utils text boundaries reject PathLike/text hooks."""
from __future__ import annotations
from Virus_Scan.detection.models.failure_state import DetectionRecoverableFailureRequest

import ast
from functools import lru_cache
from pathlib import Path

from Virus_Scan.detection.contracts.string_predicates import context_any, is_renpy_bytecode_path
from Virus_Scan.detection.contracts.tag_validation import validate_tags_for_path
from Virus_Scan.detection.models.failure_state import DetectionFailureState, failure_state_records
from Virus_Scan.utils.pathing import normalize_scan_path, scan_path_text
from Virus_Scan.utils.text_validation import tag_validation_text


class HostilePathLike:
    fspath_calls = 0
    str_calls = 0
    repr_calls = 0
    bool_calls = 0

    def __fspath__(self):  # pragma: no cover - failure is any call
        type(self).fspath_calls += 1
        raise RuntimeError("caller-owned __fspath__ must not execute")

    def __str__(self):  # pragma: no cover - failure is any call
        type(self).str_calls += 1
        raise RuntimeError("caller-owned __str__ must not execute")

    def __repr__(self):  # pragma: no cover - failure is any call
        type(self).repr_calls += 1
        raise RuntimeError("caller-owned __repr__ must not execute")

    def __bool__(self):  # pragma: no cover - failure is any call
        type(self).bool_calls += 1
        raise RuntimeError("caller-owned truthiness must not execute")


class HostileTextProperty:
    touched = 0

    @property
    def text(self):  # pragma: no cover - failure is any call
        type(self).touched += 1
        raise RuntimeError("caller-owned text property must not execute")

    def __fspath__(self):  # pragma: no cover - failure is any call
        type(self).touched += 1
        raise RuntimeError("caller-owned __fspath__ must not execute")


class HostileIterable:
    iter_calls = 0
    str_calls = 0

    def __iter__(self):  # pragma: no cover - failure is any call
        type(self).iter_calls += 1
        raise RuntimeError("caller-owned __iter__ must not execute")

    def __str__(self):  # pragma: no cover - failure is any call
        type(self).str_calls += 1
        raise RuntimeError("caller-owned __str__ must not execute")


def _reset() -> None:
    HostilePathLike.fspath_calls = 0
    HostilePathLike.str_calls = 0
    HostilePathLike.repr_calls = 0
    HostilePathLike.bool_calls = 0
    HostileTextProperty.touched = 0
    HostileIterable.iter_calls = 0
    HostileIterable.str_calls = 0


@lru_cache(maxsize=1)
def _static_guard_sources() -> tuple[Path, ...]:
    roots = (Path("Virus_Scan/detection"), Path("Virus_Scan/utils"))
    return tuple(
        source
        for root in roots
        for source in sorted(root.rglob("*.py"))
    )


@lru_cache(maxsize=None)
def _static_guard_tree(path_text: str) -> ast.Module:
    return ast.parse(Path(path_text).read_text(encoding="utf-8"), filename=path_text)


def teardown_module() -> None:
    _static_guard_sources.cache_clear()
    _static_guard_tree.cache_clear()


def test_stage1669_detection_text_boundaries_reject_pathlike_hooks() -> None:
    _reset()
    hostile = HostilePathLike()

    assert tag_validation_text(hostile) == ""
    assert context_any(hostile, ("renpy",)) is False
    assert is_renpy_bytecode_path(hostile) is False
    assert validate_tags_for_path(("process_exec",), path=hostile, strings_blob=hostile, source=hostile) == []

    assert HostilePathLike.fspath_calls == 0
    assert HostilePathLike.str_calls == 0
    assert HostilePathLike.repr_calls == 0
    assert HostilePathLike.bool_calls == 0


def test_stage1669_detection_failure_state_rejects_pathlike_and_text_property_hooks() -> None:
    _reset()
    hostile_path = HostilePathLike()
    hostile_text = HostileTextProperty()

    state = DetectionFailureState.from_recoverable_request(DetectionRecoverableFailureRequest(
        stage_name="stage-x",
        error=RuntimeError("boom"),
        error_source="detection",
        affected_context=hostile_path,
    ))
    text_property_state = DetectionFailureState.from_recoverable_request(DetectionRecoverableFailureRequest(
        stage_name="stage-x",
        error=hostile_text,
        error_source="detection",
        affected_context="ctx",
    ))
    records = failure_state_records(({"reason": hostile_text},))

    assert state.affected_context == ""
    assert text_property_state.message == "detection_failure_message_unavailable"
    assert records == ({"reason": "<HostileTextProperty>"},)
    assert HostilePathLike.fspath_calls == 0
    assert HostilePathLike.str_calls == 0
    assert HostileTextProperty.touched == 0


def test_stage1669_utils_pathing_rejects_pathlike_hooks_but_accepts_exact_path() -> None:
    _reset()
    hostile = HostilePathLike()
    exact = Path("game/renpy/script.rpy")

    assert normalize_scan_path(hostile) == ""
    assert scan_path_text(hostile) == ""
    assert normalize_scan_path(exact).replace("\\", "/").endswith("game/renpy/script.rpy")
    assert scan_path_text(exact).endswith("game/renpy/script.rpy")

    assert HostilePathLike.fspath_calls == 0
    assert HostilePathLike.str_calls == 0
    assert HostilePathLike.bool_calls == 0


def test_stage1669_unknown_iterables_are_rejected_before_iter_hooks() -> None:
    _reset()
    hostile = HostileIterable()

    assert context_any("alpha", hostile) is False
    assert validate_tags_for_path(hostile, path="game/renpy/script.rpyc") == [
        "tag_normalization_failure_evidence",
        "tag_validation_failure_evidence",
        "detection_stage_degraded",
    ]
    assert failure_state_records(hostile)[0]["unavailable_reason"] == "detection_failure_iterable_unavailable"

    assert HostileIterable.iter_calls == 0
    assert HostileIterable.str_calls == 0


def test_stage1669_detection_utils_text_boundaries_have_static_no_fspath_guard() -> None:
    offenders: list[str] = []
    for source in _static_guard_sources():
        text = source.read_text(encoding="utf-8")
        if "os.fspath" not in text and "getattr" not in text and "hasattr" not in text:
            continue
        tree = _static_guard_tree(str(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "os"
                    and func.attr == "fspath"
                    and len(node.args) == 1
                    and isinstance(node.args[0], ast.Name)
                    and node.args[0].id in {"value", "path"}
                ):
                    offenders.append(f"{source}:{node.lineno}:os.fspath({node.args[0].id})")
                if (
                    isinstance(func, ast.Name)
                    and func.id in {"getattr", "hasattr"}
                    and len(node.args) >= 2
                    and isinstance(node.args[0], ast.Name)
                    and node.args[0].id == "value"
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value in {"text", "value", "__fspath__"}
                ):
                    offenders.append(f"{source}:{node.lineno}:{func.id}(value, {node.args[1].value!r})")
    assert offenders == []
