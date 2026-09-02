from Virus_Scan.tests.support.static_inventory import parse_python_file, virus_scan_python_files

import ast



def test_production_callers_enter_scheduler_through_public_api_only():
    findings = []
    for path in virus_scan_python_files():
        rel = path.as_posix()
        if '/scheduler/' in rel or rel.startswith('Virus_Scan/tests/'):
            continue
        tree = parse_python_file(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith('Virus_Scan.scheduler'):
                if not node.module.startswith('Virus_Scan.scheduler.api'):
                    findings.append((rel, node.lineno, node.module))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith('Virus_Scan.scheduler') and not alias.name.startswith('Virus_Scan.scheduler.api'):
                        findings.append((rel, node.lineno, alias.name))
    assert findings == []
