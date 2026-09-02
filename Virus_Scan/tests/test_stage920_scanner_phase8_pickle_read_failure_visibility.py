
"""Stage 920 Phase 3/8: pickle fast read failures must not become empty byte samples."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners.pickle.escalation import pickle_fast_escalation_prefilter
from Virus_Scan.scanners.pickle.escalation_io import PICKLE_FAST_READ_FAILURE, _pickle_fast_empty_info, _pickle_fast_read_sample


def test_pickle_fast_read_sample_returns_explicit_failure_sentinel(tmp_path) -> None:
    missing = tmp_path / "missing.rpyc"
    info = _pickle_fast_empty_info()
    result = _pickle_fast_read_sample(missing, ".rpyc", info)
    assert result is PICKLE_FAST_READ_FAILURE
    assert info["force_full"] is True
    assert "pickle_fast_read_error" in info["hits"]
    assert info["tags"]


def test_pickle_fast_prefilter_preserves_read_failure_evidence(tmp_path) -> None:
    missing = tmp_path / "missing.rpyc"
    info = pickle_fast_escalation_prefilter(missing)
    assert info["force_full"] is True
    assert "pickle_fast_read_error" in info["hits"]
    assert info["tags"]


def test_pickle_fast_read_sample_has_no_empty_bytes_exception_return() -> None:
    source = read_python_file(Path("Virus_Scan/scanners/pickle/escalation_io.py"))
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            block = "\n".join(source.splitlines()[node.lineno - 1:getattr(node, "end_lineno", node.lineno)])
            assert "return b''" not in block
