from __future__ import annotations

import ast

from Virus_Scan.tests.support.static_inventory import (
    clear_static_inventory_cache,
    parse_python_file,
    virus_scan_python_files,
)


def test_rev15_static_inventory_full_ast_cache_is_session_memory_bounded() -> None:
    clear_static_inventory_cache()
    parameters = parse_python_file.cache_parameters()
    maximum = parameters["maxsize"]
    assert isinstance(maximum, int)
    assert 0 < maximum <= 32

    paths = virus_scan_python_files()[: maximum + 17]
    assert len(paths) > maximum
    for path in paths:
        assert isinstance(parse_python_file(path), ast.AST)

    info = parse_python_file.cache_info()
    assert info.maxsize == maximum
    assert info.currsize <= maximum
    clear_static_inventory_cache()
    assert parse_python_file.cache_info().currsize == 0
