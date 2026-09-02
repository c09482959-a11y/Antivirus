
"""Stage 2023 behavior bucket registry no-hook boundaries."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.detection.tags.heuristics.behavior_buckets import (
    build_behavior_bucket_index,
    tag_behavior_bucket,
)


class HostileText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("behavior bucket text conversion must not execute")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("behavior bucket repr must not execute")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("behavior bucket truthiness must not execute")


class HostileMapping(Mapping):
    touched = 0

    def __getitem__(self, _key):
        type(self).touched += 1
        raise RuntimeError("behavior bucket mapping lookup must not execute")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("behavior bucket mapping iter must not execute")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("behavior bucket mapping len must not execute")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("behavior bucket mapping items must not execute")


def test_behavior_bucket_index_rejects_hostile_mapping_and_bucket_without_hooks() -> None:
    HostileText.touched = 0
    HostileMapping.touched = 0

    hostile_index = build_behavior_bucket_index(HostileMapping())
    mixed_index = build_behavior_bucket_index({"process_exec": HostileText()})

    assert hostile_index == {}
    assert mixed_index["other_behavior"] == frozenset({"process_exec"})
    assert HostileText.touched == 0
    assert HostileMapping.touched == 0


def test_behavior_bucket_index_preserves_exact_mapping_behavior() -> None:
    index = build_behavior_bucket_index({"process_exec": "OS_EXECUTION"})

    assert index["os_execution"] == frozenset({"process_exec"})
    assert tag_behavior_bucket("bash_exec") == "script_execution"


def test_behavior_bucket_source_removes_raw_mapping_and_string_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/detection/tags/heuristics/behavior_buckets.py"))
    tree = ast.parse(source)
    forbidden = (
        'bucket = str(value or "other_behavior").strip().lower()',
        "source = TAG_TO_BEHAVIOR if tag_to_behavior is None else MappingProxyType(dict(tag_to_behavior or {}))",
        "for tag, bucket in source.items():",
        "return MappingProxyType({bucket: frozenset(values) for bucket, values in sorted(buckets.items())})",
    )
    assert [snippet for snippet in forbidden if snippet in source] == []
    assert [node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
