from __future__ import annotations

import ast
from pathlib import Path

MODEL_IMPORT_LAYOUT_ROOTS = (
    Path("Virus_Scan/models"),
    Path("Virus_Scan/runtime"),
    Path("Virus_Scan/detection/scoring"),
)

MODEL_IMPORT_LAYOUT_TEST_ROOTS = (
    Path("Virus_Scan/tests"),
    Path("tests"),
)

MODEL_IMPORT_LAYOUT_TEST_NAME_TOKENS = (
    "adaptive",
    "cluster",
    "detection",
    "graph",
    "markov",
    "model",
    "probability",
    "profile",
    "scoring",
    "temporal",
)



def _python_files() -> list[Path]:
    files: list[Path] = []
    for root in MODEL_IMPORT_LAYOUT_ROOTS:
        files.extend(sorted(root.rglob("*.py")))
    return files


def _model_test_files() -> list[Path]:
    files: list[Path] = []
    for root in MODEL_IMPORT_LAYOUT_TEST_ROOTS:
        if root.exists():
            files.extend(
                path
                for path in sorted(root.glob("test_*.py"))
                if any(token in path.name for token in MODEL_IMPORT_LAYOUT_TEST_NAME_TOKENS)
            )
    return files


class _FunctionImportVisitor(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.function_stack: list[str] = []
        self.violations: list[str] = []

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.function_stack.append(node.name)
        try:
            self.generic_visit(node)
        finally:
            self.function_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Import(self, node: ast.Import) -> None:
        if self.function_stack:
            self.violations.append(f"{self.path}:{node.lineno}:{self.function_stack[-1]}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if self.function_stack:
            self.violations.append(f"{self.path}:{node.lineno}:{self.function_stack[-1]}")
        self.generic_visit(node)


def test_stage1188_model_runtime_scoring_code_has_no_function_scope_imports() -> None:
    violations: list[str] = []
    for path in _python_files():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        visitor = _FunctionImportVisitor(path)
        visitor.visit(tree)
        violations.extend(visitor.violations)

    assert violations == []


def test_stage1188_model_runtime_scoring_imports_are_static_top_level_before_runtime_state() -> None:
    violations: list[str] = []
    for path in _python_files():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        saw_runtime_statement = False
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if saw_runtime_statement:
                    violations.append(f"{path}:{node.lineno}")
            elif isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant) and isinstance(node.value.value, str):
                continue
            else:
                saw_runtime_statement = True

    assert violations == []


def test_stage1188_model_phase1_python_files_do_not_import_importlib() -> None:
    violations: list[str] = []
    for path in _python_files():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "importlib" or alias.name.startswith("importlib."):
                        violations.append(f"{path}:{node.lineno}:{alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module == "importlib" or module.startswith("importlib."):
                    violations.append(f"{path}:{node.lineno}:{module}")

    assert violations == []


def test_stage1190_model_related_tests_do_not_use_mutable_module_globals() -> None:
    violations: list[str] = []
    for path in _model_test_files():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.value, (ast.Dict, ast.List, ast.Set)):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        violations.append(f"{path}:{node.lineno}:{target.id}")
            elif isinstance(node, ast.AnnAssign) and isinstance(node.value, (ast.Dict, ast.List, ast.Set)):
                target = node.target
                if isinstance(target, ast.Name):
                    violations.append(f"{path}:{node.lineno}:{target.id}")

    assert violations == []
