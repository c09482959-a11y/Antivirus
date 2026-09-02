from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.runtime import resource_paths


def test_stage2038_nuitka_marker_is_annotated_for_static_tools_without_runtime_binding() -> None:
    source = read_python_file(Path("Virus_Scan/runtime/resource_paths.py"))

    assert "__compiled__: object" in source
    assert "marker = __compiled__" in source
    assert not hasattr(resource_paths, "__compiled__")
    assert resource_paths._nuitka_compiled_marker() is False
