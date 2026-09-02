import ast
from pathlib import Path

import Virus_Scan.scanners.binary as binary_scanner
from Virus_Scan.scanners import binary_resource_metrics


def test_binary_scanner_import_does_not_require_posix_resource_module():
    source = Path(binary_scanner.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    top_level_imports = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            top_level_imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            top_level_imports.append(node.module or "")
    assert "resource" not in top_level_imports
    assert callable(binary_resource_metrics._umige_process_rss_mb)
    assert not hasattr(binary_scanner, "_umige_process_rss_mb")
