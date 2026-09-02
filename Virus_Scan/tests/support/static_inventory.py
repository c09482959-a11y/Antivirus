"""Cached static-analysis inventory for pytest architecture guards.

The architecture tests intentionally parse actual repository source.  Several
independent guard files need the same file lists and AST/import summaries; this
module centralizes deterministic discovery and bounded source-derived caches so
full-suite validation does not repeatedly walk or parse the same repository
files.
"""
from __future__ import annotations

import ast
import io
import os
import re
import tokenize
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_REPOSITORY_PYTHON_ROOTS = (_REPOSITORY_ROOT / "Virus_Scan", _REPOSITORY_ROOT / "tests")
_TEST_ROOTS = (_REPOSITORY_ROOT / "Virus_Scan" / "tests", _REPOSITORY_ROOT / "tests")
_IGNORED_DIR_NAMES = frozenset({"__pycache__", ".pytest_cache"})


def _python_files_below(root: Path) -> tuple[Path, ...]:
    if not root.exists():
        return ()
    files: list[Path] = []
    for current_root, dir_names, file_names in os.walk(root):
        dir_names[:] = sorted(name for name in dir_names if name not in _IGNORED_DIR_NAMES)
        current_path = Path(current_root)
        for file_name in sorted(file_names):
            if file_name.endswith(".py"):
                files.append(current_path / file_name)
    return tuple(files)


@lru_cache(maxsize=1)
def repository_python_files() -> tuple[Path, ...]:
    files: list[Path] = []
    for root in _REPOSITORY_PYTHON_ROOTS:
        files.extend(_python_files_below(root))
    return tuple(sorted(files))


@lru_cache(maxsize=1)
def top_level_test_files() -> tuple[Path, ...]:
    files: list[Path] = []
    for root in _TEST_ROOTS:
        if root.exists():
            files.extend(sorted(root.glob("test_*.py")))
    return tuple(files)


def _exclude_package_test_files(files: tuple[Path, ...]) -> tuple[Path, ...]:
    return tuple(path for path in files if path.parent != (_REPOSITORY_ROOT / "Virus_Scan" / "tests") and "tests" not in path.relative_to(_REPOSITORY_ROOT / "Virus_Scan").parts)


@lru_cache(maxsize=1)
def virus_scan_python_files() -> tuple[Path, ...]:
    return _exclude_package_test_files(_python_files_below(_REPOSITORY_ROOT / "Virus_Scan"))


@lru_cache(maxsize=None)
def python_files_under(relative_root: str) -> tuple[Path, ...]:
    files = _python_files_below(_REPOSITORY_ROOT / relative_root)
    if relative_root.rstrip("/") == "Virus_Scan":
        return _exclude_package_test_files(files)
    return files


@lru_cache(maxsize=None)
def read_python_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


_FROM_IMPORT_RE = re.compile(r"^\s*from\s+([A-Za-z_][\w.]*)\s+import\s+")
_IMPORT_RE = re.compile(r"^\s*import\s+(.+)$")


@lru_cache(maxsize=None)
def import_modules(path: Path) -> tuple[str, ...]:
    """Return imported module names using bounded text scanning.

    The architecture guards that use this helper only need import ownership
    evidence.  Building and retaining full ASTs for every repository file during
    full-suite validation can turn these guards into a collection/runtime
    blocker.  This scanner intentionally records import targets from source
    lines without retaining AST nodes, while still detecting top-level and
    function-local import statements.
    """
    modules: list[str] = []
    for line in read_python_file(path).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        from_match = _FROM_IMPORT_RE.match(line)
        if from_match:
            modules.append(from_match.group(1))
            continue
        import_match = _IMPORT_RE.match(line)
        if not import_match:
            continue
        for part in import_match.group(1).split(","):
            module = part.strip().split(" as ", 1)[0].strip()
            if module:
                modules.append(module)
    return tuple(modules)




@lru_cache(maxsize=None)
def from_imported_names(path: Path, module_name: str) -> tuple[tuple[int, str], ...]:
    """Return names imported from one module using bounded source scanning.

    This is intentionally narrower than parsing and retaining every repository
    AST for simple forbidden-from-import architecture guards.  It supports
    ordinary single-line imports and parenthesized multi-line import blocks,
    which covers current-source guard usage without adding full-suite AST
    pressure.
    """
    findings: list[tuple[int, str]] = []
    lines = read_python_file(path).splitlines()
    index = 0
    prefix = f"from {module_name} import"
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or not stripped.startswith(prefix):
            index += 1
            continue
        lineno = index + 1
        remainder = stripped[len(prefix):].strip()
        while remainder.startswith("(") and ")" not in remainder and index + 1 < len(lines):
            index += 1
            remainder = f"{remainder} {lines[index].strip()}"
        remainder = remainder.strip("()")
        for part in remainder.split(","):
            name = part.strip().split(" as ", 1)[0].strip()
            if name:
                findings.append((lineno, name))
        index += 1
    return tuple(findings)


# Full AST object graphs are intentionally bounded.  Repository-wide architecture
# guards can parse hundreds of modules in one test; retaining every AST for the
# entire pytest session adds hundreds of MiB of cumulative RSS.  Source text and
# compact derived findings remain independently cached; AST identity is not a
# cross-test semantic contract.
_STATIC_AST_CACHE_MAXSIZE = 32


@lru_cache(maxsize=_STATIC_AST_CACHE_MAXSIZE)
def parse_python_file(path: Path) -> ast.AST:
    return ast.parse(read_python_file(path), filename=str(path))


_LOCAL_IMPORT_LINE = re.compile(r"^\s*(?:from\s+[A-Za-z_][\w.]*\s+import\s+|import\s+)")
_DYNAMIC_IMPORT_LINE = re.compile(r"\b(?:import_module|__import__)\s*\(")
_FUNCTION_HEADER_LINE = re.compile(r"^(?P<indent>\s*)(?:async\s+def|def)\s+(?P<name>[A-Za-z_]\w*)\b")




@lru_cache(maxsize=None)
def local_import_and_dynamic_import_findings(path: Path) -> tuple[str, ...]:
    """Return function-local import and dynamic import findings for one file.

    Uses bounded line scanning with triple-quoted string suppression so full
    pytest does not spend minutes tokenizing or retaining every test/source AST.
    """
    findings: list[str] = []
    function_stack: list[tuple[int, str]] = []
    pending_function: tuple[int, str] | None = None
    in_triple_quote = False

    for lineno, line in enumerate(read_python_file(path).splitlines(), 1):
        probe = line
        if in_triple_quote:
            if "\"\"\"" in probe:
                probe = probe.split("\"\"\"", 1)[1]
                in_triple_quote = False
            else:
                continue
        if "\"\"\"" in probe:
            before, _sep, _after = probe.partition("\"\"\"")
            probe = before
            in_triple_quote = True
        stripped = probe.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(probe) - len(probe.lstrip(" \t"))
        while function_stack and indent <= function_stack[-1][0]:
            function_stack.pop()
        if pending_function is not None and indent > pending_function[0]:
            function_stack.append(pending_function)
            pending_function = None
        function_match = _FUNCTION_HEADER_LINE.match(probe)
        if function_match:
            pending_function = (len(function_match.group("indent")), function_match.group("name"))
        elif function_stack and _LOCAL_IMPORT_LINE.match(probe):
            findings.append(f"{path}:{lineno}: function-local import in {function_stack[-1][1]}")
        if _DYNAMIC_IMPORT_LINE.search(probe):
            findings.append(f"{path}:{lineno}: dynamic import call")
    return tuple(findings)



_BARE_EXCEPT_LINE = re.compile(r"^\s*except\s*:")
_BROAD_EXCEPTION_LINE = re.compile(r"^\s*except\s+Exception\s*(?:as\s+[A-Za-z_]\w*)?\s*:")


@lru_cache(maxsize=None)
def bare_or_broad_exception_findings(path: Path) -> tuple[str, ...]:
    """Return bare/broad exception handlers using bounded source scanning."""
    findings: list[str] = []
    for lineno, line in enumerate(read_python_file(path).splitlines(), 1):
        if _BARE_EXCEPT_LINE.match(line):
            findings.append(f"{path}:{lineno}:bare_except")
        elif _BROAD_EXCEPTION_LINE.match(line):
            findings.append(f"{path}:{lineno}:broad_exception")
    return tuple(findings)


_TOP_LEVEL_MUTABLE_LITERAL_TOKENS = frozenset({"[", "{"})


def _source_needs_module_mutable_ast_scan(source: str) -> bool:
    """Return whether a module can contain top-level list/set/dict binds.

    The Stage1764 guard only rejects AST ``List``, ``Set``, and ``Dict``
    literals assigned directly in ``tree.body``.  Most production modules do not
    contain such top-level literal assignment candidates, so a bounded source
    prefilter avoids reparsing every module during cumulative full-suite runs.
    It may over-include ambiguous multi-line top-level assignments, but it must
    not skip a line that can contain a direct mutable literal assignment.
    """
    for line in source.splitlines():
        if line.startswith((" ", "\t")):
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        if any(token in stripped for token in _TOP_LEVEL_MUTABLE_LITERAL_TOKENS):
            return True
        if stripped.endswith(("=", "(", "\\")):
            return True
    return False


@lru_cache(maxsize=None)
def module_level_mutable_assignment_findings(path: Path) -> tuple[tuple[str, int, str], ...]:
    """Return top-level list/set/dict assignment findings for one module."""
    source = read_python_file(path)
    if not _source_needs_module_mutable_ast_scan(source):
        return ()

    findings: list[tuple[str, int, str]] = []
    tree = parse_python_file(path)
    if not isinstance(tree, ast.Module):
        return ()
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if isinstance(value, (ast.List, ast.Set, ast.Dict)):
            findings.append((str(path), node.lineno, type(value).__name__))
    return tuple(findings)


_LITERAL_PLACEHOLDER_ASSERT = re.compile(r"^\s*assert\s+(?:True|False|None)\s*(?:#.*)?$")


@lru_cache(maxsize=None)
def literal_placeholder_assertion_findings(path: Path) -> tuple[str, ...]:
    """Return literal placeholder assert findings without retaining test ASTs."""
    findings: list[str] = []
    for lineno, line in enumerate(read_python_file(path).splitlines(), 1):
        if _LITERAL_PLACEHOLDER_ASSERT.match(line):
            findings.append(f"{path}:{lineno}: literal placeholder assertion")
    return tuple(findings)



_HIDDEN_FAILURE_NAMES = frozenset({"skip", "skipif", "xfail"})
_ASSERTION_CONTEXT_NAMES = frozenset({"raises"})


@dataclass
class _AssertionScanFunction:
    indent: int
    line: int
    name: str
    has_assertion: bool = False


@lru_cache(maxsize=None)
def hidden_failure_test_hygiene_findings(path: Path) -> tuple[str, ...]:
    """Return skip/xfail/monkeypatch hygiene findings without AST retention."""
    findings: list[str] = []
    rel = repository_relative_path(path)
    tokens = tokenize.generate_tokens(io.StringIO(read_python_file(path)).readline)
    for tok in tokens:
        if tok.type != tokenize.NAME:
            continue
        if tok.string in _HIDDEN_FAILURE_NAMES or tok.string == "monkeypatch":
            findings.append(f"{rel}:{tok.start[0]}:{tok.string}")
    return tuple(findings)


@lru_cache(maxsize=None)
def assertion_free_test_function_findings(path: Path) -> tuple[str, ...]:
    """Return assertion-free test function findings without retaining ASTs."""
    findings: list[str] = []
    rel = repository_relative_path(path)
    function_stack: list[_AssertionScanFunction] = []
    pending_def: tuple[int, str] | None = None
    tokens = tuple(tokenize.generate_tokens(io.StringIO(read_python_file(path)).readline))

    def close_function(record: _AssertionScanFunction) -> None:
        if record.name.startswith("test_") and not record.has_assertion:
            findings.append(f"{rel}:{record.line}:{record.name}")

    for index, tok in enumerate(tokens):
        if tok.type == tokenize.DEDENT:
            while function_stack and function_stack[-1].indent > tok.start[1]:
                close_function(function_stack.pop())
            continue
        if tok.type == tokenize.INDENT:
            if pending_def is not None:
                def_line, def_name = pending_def
                function_stack.append(_AssertionScanFunction(len(tok.string), def_line, def_name))
                pending_def = None
            continue
        if tok.type == tokenize.NAME and tok.string == "def":
            lookahead = index + 1
            while lookahead < len(tokens) and tokens[lookahead].type in (tokenize.NL, tokenize.NEWLINE):
                lookahead += 1
            if lookahead < len(tokens) and tokens[lookahead].type == tokenize.NAME:
                pending_def = (tok.start[0], tokens[lookahead].string)
        elif function_stack and tok.type == tokenize.NAME and (tok.string == "assert" or tok.string in _ASSERTION_CONTEXT_NAMES):
            function_stack[-1].has_assertion = True
    while function_stack:
        close_function(function_stack.pop())
    return tuple(findings)


_BOUNDED_SUBPROCESS_CALL_NAMES = frozenset({"run", "call", "check_call", "check_output"})


@lru_cache(maxsize=None)
def unbounded_subprocess_timeout_findings(path: Path) -> tuple[str, ...]:
    """Return subprocess calls in tests that lack an explicit timeout."""
    findings: list[str] = []
    rel = repository_relative_path(path)
    tokens = tuple(tokenize.generate_tokens(io.StringIO(read_python_file(path)).readline))
    index = 0
    while index < len(tokens) - 3:
        tok = tokens[index]
        if not (tok.type == tokenize.NAME and tok.string == "subprocess"):
            index += 1
            continue
        dot = tokens[index + 1]
        name = tokens[index + 2]
        open_paren = tokens[index + 3]
        if dot.string != "." or name.type != tokenize.NAME or name.string not in _BOUNDED_SUBPROCESS_CALL_NAMES:
            index += 1
            continue
        if open_paren.string != "(":
            index += 1
            continue
        depth = 0
        has_timeout = False
        cursor = index + 3
        while cursor < len(tokens):
            current = tokens[cursor]
            if current.string == "(":
                depth += 1
            elif current.string == ")":
                depth -= 1
                if depth == 0:
                    break
            elif depth >= 1 and current.type == tokenize.NAME and current.string == "timeout":
                has_timeout = True
            cursor += 1
        if not has_timeout:
            findings.append(f"{rel}:{tok.start[0]}:subprocess.{name.string}")
        index = max(cursor + 1, index + 1)
    return tuple(findings)




_WILDCARD_FROM_IMPORT_RE = re.compile(r"^\s*from\s+([A-Za-z_][\w.]*)\s+import\s+\*")


@lru_cache(maxsize=None)
def wildcard_import_findings(path: Path) -> tuple[str, ...]:
    """Return wildcard import findings using bounded source-line scanning."""
    findings: list[str] = []
    for lineno, line in enumerate(read_python_file(path).splitlines(), 1):
        match = _WILDCARD_FROM_IMPORT_RE.match(line)
        if match:
            findings.append(f"{path}:{lineno}:{match.group(1)}")
    return tuple(findings)

@lru_cache(maxsize=None)
def repository_relative_path(path: Path) -> Path:
    return path.relative_to(_REPOSITORY_ROOT)


def clear_static_inventory_cache() -> None:
    """Release cached source-analysis snapshots before pytest interpreter teardown."""
    repository_python_files.cache_clear()
    top_level_test_files.cache_clear()
    virus_scan_python_files.cache_clear()
    python_files_under.cache_clear()
    read_python_file.cache_clear()
    parse_python_file.cache_clear()
    import_modules.cache_clear()
    from_imported_names.cache_clear()
    wildcard_import_findings.cache_clear()
    local_import_and_dynamic_import_findings.cache_clear()
    bare_or_broad_exception_findings.cache_clear()
    module_level_mutable_assignment_findings.cache_clear()
    literal_placeholder_assertion_findings.cache_clear()
    hidden_failure_test_hygiene_findings.cache_clear()
    assertion_free_test_function_findings.cache_clear()
    unbounded_subprocess_timeout_findings.cache_clear()
    repository_relative_path.cache_clear()
