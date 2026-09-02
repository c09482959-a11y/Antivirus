from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners.binary_failover import should_binary_failover


class _BadExt:
    touched = 0

    def __str__(self) -> str:
        type(self).touched += 1
        raise ValueError('bad extension object')

    def __repr__(self) -> str:
        type(self).touched += 1
        raise ValueError('bad extension repr')


def test_binary_failover_ext_conversion_failure_emits_scanner_evidence():
    tags: list[str] = []
    _BadExt.touched = 0

    assert should_binary_failover('unknown', 'unknown', {'magic_stage': 'unknown', 'magic_type': 'unknown', 'ext': _BadExt()}, [], tags) is True

    assert _BadExt.touched == 0
    assert 'binary_failover_identity_malformed' in tags
    assert 'binary_failover_final_json_must_record' in tags
    assert 'scanner_failure_evidence_recorded' in tags
    assert 'scanner_failure_evidence:binary:should_binary_failover_renpy_identity' in tags


def test_binary_failover_malformed_identity_still_emits_public_evidence():
    tags: list[str] = []

    assert should_binary_failover('unknown', 'unknown', 'not-a-mapping', [], tags) is True

    assert 'binary_failover_identity_malformed' in tags
    assert 'binary_failover_final_json_must_record' in tags
    assert 'scanner_failure_evidence:binary:should_binary_failover_identity' in tags


def test_binary_failover_no_suppressed_failure_callsite_remains():
    source = read_python_file(Path('Virus_Scan/scanners/binary_failover.py'))
    tree = ast.parse(source)

    suppressed_calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, 'id', getattr(node.func, 'attr', '')) == 'record_suppressed_failure'
    ]

    assert suppressed_calls == []
