"""Architectural entropy and mutation-density audit helpers."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PosixPath, WindowsPath
import os
import re



@dataclass(frozen=True)
class ModuleEntropyRecord:
    path: str
    imports: int
    broad_handlers: int
    dynamic_access: int
    function_defs: int
    class_defs: int
    mutation_writes: int

    @property
    def score(self) -> int:
        return self.imports + (self.broad_handlers * 5) + (self.dynamic_access * 3) + (self.mutation_writes * 2) + self.function_defs + (self.class_defs * 2)

    def canonical(self) -> dict[str, object]:
        return {"path": self.path, "imports": self.imports, "broad_handlers": self.broad_handlers, "dynamic_access": self.dynamic_access, "function_defs": self.function_defs, "class_defs": self.class_defs, "mutation_writes": self.mutation_writes, "score": self.score}


_FROM_IMPORT_LINE = re.compile(r"^\s*from\s+\S+\s+import\s+(.+)$")
_IMPORT_LINE = re.compile(r"^\s*import\s+(.+)$")
_FUNCTION_LINE = re.compile(r"^\s*(?:async\s+def|def)\s+\w+")
_CLASS_LINE = re.compile(r"^\s*class\s+\w+")
_DYNAMIC_ACCESS_CALL = re.compile(r"\b(?:getattr|setattr|globals|locals|eval|exec)\s*\(")
_ATTRIBUTE_OR_SUBSCRIPT_WRITE = re.compile(r"(?:\b\w+\.\w+|\[[^\]]+\])\s*(?::[^=]+)?[+\-*/%|&^]?=")


def _split_import_targets(raw_targets: str) -> int:
    targets = [part.strip() for part in raw_targets.split(",")]
    return sum(1 for target in targets if target and target != "(")


def _entropy_record_for_source(path: Path, relative_path: str, source: str) -> ModuleEntropyRecord:
    del path  # Explicitly unused contract parameters.
    imports = 0
    broad_handlers = 0
    dynamic_access = 0
    function_defs = 0
    class_defs = 0
    mutation_writes = 0

    for line in source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        from_match = _FROM_IMPORT_LINE.match(line)
        if from_match:
            imports += _split_import_targets(from_match.group(1))
        else:
            import_match = _IMPORT_LINE.match(line)
            if import_match:
                imports += _split_import_targets(import_match.group(1))
        if stripped.startswith(("except:", "except Exception", "except BaseException")):
            broad_handlers += 1
        dynamic_access += len(_DYNAMIC_ACCESS_CALL.findall(line))
        if _FUNCTION_LINE.match(line):
            function_defs += 1
        if _CLASS_LINE.match(line):
            class_defs += 1
        if _ATTRIBUTE_OR_SUBSCRIPT_WRITE.search(line):
            mutation_writes += 1

    return ModuleEntropyRecord(
        relative_path,
        imports,
        broad_handlers,
        dynamic_access,
        function_defs,
        class_defs,
        mutation_writes,
    )

def audit_entropy(root: str | Path) -> dict[str, object]:
    if type(root) is str:
        root = Path(str.__str__(root))
    elif type(root) not in (PosixPath, WindowsPath):
        exception_message = "entropy governance root rejected"
        raise TypeError(exception_message)
    records: list[ModuleEntropyRecord] = []
    ignored_dirs = {"__pycache__", "tests", ".pytest_cache"}
    python_files: list[Path] = []
    for current_root, dir_names, file_names in os.walk(root):
        dir_names[:] = sorted(name for name in dir_names if name not in ignored_dirs)
        current_path = Path(current_root)
        python_files.extend(
            current_path / file_name
            for file_name in sorted(file_names)
            if file_name.endswith(".py")
        )
    for py in python_files:
        source = py.read_text(encoding="utf-8", errors="replace")
        records.append(_entropy_record_for_source(py, py.relative_to(root).as_posix(), source))
    totals = {
        "modules": len(records),
        "broad_handlers": sum(r.broad_handlers for r in records),
        "dynamic_access": sum(r.dynamic_access for r in records),
        "mutation_writes": sum(r.mutation_writes for r in records),
    }
    hot = sorted((r.canonical() for r in records), key=lambda r: (-r["score"], r["path"]))[:25]
    return {"totals": totals, "hotspots": hot}


__all__ = ("ModuleEntropyRecord", "audit_entropy")
