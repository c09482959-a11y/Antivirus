from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.models import learning as learning_owner
from Virus_Scan.models.graph import scan as graph_scan
from Virus_Scan.models.markov import counters as markov_counters
from Virus_Scan.models.markov.counters import counter_support, counter_target_count


class HostileText:
    touched = 0

    def __str__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise AssertionError("text hook executed")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("repr hook executed")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("format hook executed")


class HostileMappingLike:
    touched = 0

    def items(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise AssertionError("items hook executed")

    def get(self, _key, _default=None):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("get hook executed")


def _function_named(tree: ast.AST, name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"missing function {name}")


def test_stage2014_graph_scan_source_removes_reopened_unsafe_rows() -> None:
    source = read_python_file(Path("Virus_Scan/models/graph/scan.py"))

    assert "for tag, pattern in _CS_GRAPH_REGEX_TAGS.items():" not in source
    assert "log_error(f'graph regex tag evaluation failed without synthetic substitute: {e}')" not in source
    assert "log_error(f'graph analysis step failed without synthetic substitute: {e}')" not in source
    assert "ordered_tags = sorted((safe_graph_text(tag) for tag in tags), key=safe_graph_text)" not in source
    assert "for mname, body in methods.items():" not in source
    assert "fid = f'{file}::{mname}'" not in source

    tree = ast.parse(source)
    assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(tree))


def test_stage2014_graph_tag_ordering_rejects_hostile_text_without_hooks() -> None:
    HostileText.touched = 0

    ordered = graph_scan._ordered_graph_tags({"zeta", HostileText(), "alpha"})

    assert ordered == ["alpha", "zeta"]
    assert HostileText.touched == 0


def test_stage2014_learning_guard_uses_owned_thread_state_without_getattr_bool_route() -> None:
    source = read_python_file(Path("Virus_Scan/models/learning.py"))
    assert 'getattr(_LEARNING_REENTRY_STATE, "active", False)' not in source
    assert "return bool(" not in source

    state = learning_owner._learning_state()
    previous = dict(state)
    try:
        state.clear()
        assert learning_owner._learning_in_progress() is False
        with learning_owner.learning_guard() as entered:
            assert entered is True
            assert learning_owner._learning_in_progress() is True
            with learning_owner.learning_guard() as nested:
                assert nested is False
        assert learning_owner._learning_in_progress() is False
    finally:
        state.clear()
        state.update(previous)


def test_stage2014_markov_type_probe_has_no_exception_sentinel_return() -> None:
    source = read_python_file(Path("Virus_Scan/models/markov/counters.py"))
    tree = ast.parse(source)
    function = _function_named(tree, "_type_defines_callable")

    returns_in_handlers = []
    for handler in [node for node in ast.walk(function) if isinstance(node, ast.ExceptHandler)]:
        returns_in_handlers.extend(node.lineno for node in ast.walk(handler) if isinstance(node, ast.Return))

    assert returns_in_handlers == []
    assert "except (AttributeError, TypeError):\n        return False" not in source


def test_stage2014_markov_mapping_like_probe_still_rejects_without_hooks() -> None:
    HostileMappingLike.touched = 0
    hostile = HostileMappingLike()

    assert counter_support(hostile) == (0, 0, "unreadable_markov_transition_counter")
    assert counter_target_count(hostile, "target") == (0, "unreadable_markov_target_count")

    assert markov_counters._type_defines_callable(hostile, "items") is True
    assert HostileMappingLike.touched == 0


def test_stage2014_markov_flow_probability_sources_remove_wrapper_rows() -> None:
    flow_source = read_python_file(Path("Virus_Scan/models/markov/flow.py"))
    probability_source = read_python_file(Path("Virus_Scan/models/markov/probability.py"))
    evidence_source = read_python_file(Path("Virus_Scan/models/markov/evidence.py"))
    feature_source = read_python_file(Path("Virus_Scan/models/markov/features.py"))

    assert "def safe_markov_stage_name(value: Any) -> str:\n    return safe_markov_text(value, default_text='unknown')" not in flow_source
    assert "source=safe_markov_stage_name(source)," not in evidence_source
    assert "target=safe_markov_stage_name(target)," not in evidence_source
    assert "target = safe_markov_stage_name(curr_stage)" in probability_source
    assert "source = safe_markov_stage_name(prev_stage)" in probability_source
    assert "mf = compute_markov_features(safe_markov_stage_name(prev_stage), tags, safe_markov_stage_name(curr_stage))" not in feature_source
    assert "pair_baseline.get((a, b), 0)" not in feature_source
    assert "trans.get(b, 0)" not in feature_source
    assert "record.get('ready')" not in feature_source
