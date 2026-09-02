"""Release source-manifest guard for Virus_Scan Python package files.

The release builder must compare a candidate ZIP/tree with the previous good
release before publishing. If any ``Virus_Scan/**/*.py`` source file from the
previous release is missing, the release is blocked unless candidate audit
Markdown explicitly authorizes that deletion. Candidate source and audit packages
are also blocked when persistent YARA runtime artifacts are present.
"""
from __future__ import annotations

from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
import re
import sys
from zipfile import ZipFile

SOURCE_PREFIX = "Virus_Scan/"
SOURCE_SUFFIX = ".py"
AUDIT_PREFIX = "Audit/"
AUDIT_SUFFIX = ".md"
DELETE_AUTH_RE = re.compile(r"\bSOURCE_DELETE_AUTHORIZED:\s*`?(Virus_Scan/[^\s`|#]+\.py)`?")
PACKAGE_DELETE_AUTH_RE = re.compile(r"\bSOURCE_PACKAGE_DELETE_AUTHORIZED:\s*`?(Virus_Scan/[^\s`|#]+/)`?")

APPROVED_YARA_PACKAGE_RESOURCES = frozenset({
    "readme.md",
    "yara_defaults.toml",
    "yara_config.toml",
    "yara_config.schema.json",
    "yara_resource_manifest.json",
    "yara-forge-rules-core.zip",
    "yara-forge-rules-extended.zip",
})


@dataclass(frozen=True)
class AuditAuthorizations:
    file_paths: frozenset[str]
    package_prefixes: frozenset[str]


@dataclass(frozen=True)
class ManifestComparison:
    baseline_count: int
    candidate_count: int
    missing: tuple[str, ...]
    authorized_missing: tuple[str, ...]
    unauthorized_missing: tuple[str, ...]
    forbidden_runtime_artifacts: tuple[str, ...]

    @property
    def release_blocked(self) -> bool:
        return bool(self.unauthorized_missing or self.forbidden_runtime_artifacts)


def _normalized_zip_name(name: str) -> str:
    return name.replace("\\", "/").lstrip("./")


def _is_source_path(name: str) -> bool:
    normalized = _normalized_zip_name(name)
    if not normalized.startswith(SOURCE_PREFIX) or not normalized.endswith(SOURCE_SUFFIX):
        return False
    return "__pycache__" not in normalized.split("/")




def _is_forbidden_yara_runtime_artifact(name: str) -> bool:
    normalized = _normalized_zip_name(name)
    if not normalized:
        return False
    parts = tuple(part for part in normalized.split("/") if part)
    lowered = tuple(part.lower() for part in parts)
    if not parts:
        return False
    if lowered == ("yara",):
        return False
    if (
        len(lowered) == 2
        and lowered[0] == "yara"
        and lowered[1] in APPROVED_YARA_PACKAGE_RESOURCES
    ):
        return False
    yara_positions = tuple(index for index, part in enumerate(lowered) if part == "yara")
    if yara_positions:
        allowed_positions: set[int] = set()
        if lowered[:2] == ("virus_scan", "yara"):
            allowed_positions.add(1)
        if lowered[:4] == ("virus_scan", "detection", "scoring", "yara"):
            allowed_positions.add(3)
        if any(position not in allowed_positions for position in yara_positions):
            return True
    if any(part in {"yara.cache", "yaralight.cache", "yara.groups"} for part in lowered):
        return True
    filename = lowered[-1]
    if filename == ".umige-yara.lock" or filename.endswith(".yarc"):
        return True
    if filename in APPROVED_YARA_PACKAGE_RESOURCES.difference({"readme.md"}):
        return True
    if filename.startswith("yara-forge-rules-") and filename.endswith((".zip", ".txt")):
        return True
    if re.fullmatch(r"yara_(?:core|extended|full)_state\.json", filename):
        return True
    if "yara" in filename and (
        filename.endswith(".download.tmp")
        or ".tmp-" in filename
        or filename.endswith(".lock")
    ):
        return True
    return False


def forbidden_yara_runtime_artifacts_from_path(path: Path) -> tuple[str, ...]:
    if path.is_dir():
        names = (item.relative_to(path).as_posix() for item in path.rglob("*"))
    else:
        with ZipFile(path) as zf:
            names = tuple(zf.namelist())
    return tuple(sorted({
        _normalized_zip_name(name)
        for name in names
        if _is_forbidden_yara_runtime_artifact(name)
    }))


def source_manifest_from_zip(path: Path) -> frozenset[str]:
    with ZipFile(path) as zf:
        return frozenset(
            _normalized_zip_name(name)
            for name in zf.namelist()
            if _is_source_path(name)
        )


def source_manifest_from_tree(root: Path) -> frozenset[str]:
    source_root = root / "Virus_Scan"
    if not source_root.exists():
        return frozenset()
    source_paths: set[str] = set()
    for path in source_root.rglob("*.py"):
        relative = path.relative_to(root).as_posix()
        if _is_source_path(relative):
            source_paths.add(relative)
    return frozenset(source_paths)


def source_manifest_from_path(path: Path) -> frozenset[str]:
    if path.is_dir():
        return source_manifest_from_tree(path)
    return source_manifest_from_zip(path)


def _audit_texts_from_zip(path: Path) -> tuple[str, ...]:
    texts: list[str] = []
    with ZipFile(path) as zf:
        for name in zf.namelist():
            normalized = _normalized_zip_name(name)
            if not normalized.startswith(AUDIT_PREFIX) or not normalized.endswith(AUDIT_SUFFIX):
                continue
            texts.append(zf.read(name).decode("utf-8", errors="replace"))
    return tuple(texts)


def _audit_texts_from_tree(root: Path) -> tuple[str, ...]:
    audit_root = root / "Audit"
    if not audit_root.exists():
        return ()
    return tuple(
        path.read_text(encoding="utf-8", errors="replace")
        for path in audit_root.rglob("*.md")
    )


def _audit_texts_from_path(path: Path) -> tuple[str, ...]:
    if path.is_dir():
        return _audit_texts_from_tree(path)
    return _audit_texts_from_zip(path)


def _normalized_package_prefix(prefix: str) -> str:
    normalized = _normalized_zip_name(prefix)
    return normalized if normalized.endswith("/") else normalized + "/"


def audit_authorizations_from_path(path: Path) -> AuditAuthorizations:
    file_paths: set[str] = set()
    package_prefixes: set[str] = set()
    for text in _audit_texts_from_path(path):
        for match in DELETE_AUTH_RE.finditer(text):
            file_paths.add(_normalized_zip_name(match.group(1)))
        for match in PACKAGE_DELETE_AUTH_RE.finditer(text):
            package_prefixes.add(_normalized_package_prefix(match.group(1)))
    return AuditAuthorizations(
        file_paths=frozenset(file_paths),
        package_prefixes=frozenset(package_prefixes),
    )


def _is_authorized(path: str, authorizations: AuditAuthorizations) -> bool:
    if path in authorizations.file_paths:
        return True
    return any(path.startswith(prefix) for prefix in authorizations.package_prefixes)


def compare_release_manifests(baseline: Path, candidate: Path) -> ManifestComparison:
    baseline_manifest = source_manifest_from_path(baseline)
    candidate_manifest = source_manifest_from_path(candidate)
    authorizations = audit_authorizations_from_path(candidate)
    missing = tuple(sorted(baseline_manifest.difference(candidate_manifest)))
    authorized = tuple(path for path in missing if _is_authorized(path, authorizations))
    unauthorized = tuple(path for path in missing if not _is_authorized(path, authorizations))
    return ManifestComparison(
        baseline_count=len(baseline_manifest),
        candidate_count=len(candidate_manifest),
        missing=missing,
        authorized_missing=authorized,
        unauthorized_missing=unauthorized,
        forbidden_runtime_artifacts=forbidden_yara_runtime_artifacts_from_path(candidate),
    )


def _print_comparison(comparison: ManifestComparison) -> None:
    print(f"BASELINE_SOURCE_COUNT {comparison.baseline_count}")
    print(f"CANDIDATE_SOURCE_COUNT {comparison.candidate_count}")
    print(f"MISSING_SOURCE_COUNT {len(comparison.missing)}")
    print(f"AUTHORIZED_MISSING_SOURCE_COUNT {len(comparison.authorized_missing)}")
    print(f"UNAUTHORIZED_MISSING_SOURCE_COUNT {len(comparison.unauthorized_missing)}")
    print(f"FORBIDDEN_YARA_RUNTIME_ARTIFACT_COUNT {len(comparison.forbidden_runtime_artifacts)}")
    if comparison.release_blocked:
        print("RELEASE_MANIFEST_GUARD_FAILED")
        for path in comparison.unauthorized_missing:
            print(f"UNAUTHORIZED_MISSING_SOURCE {path}")
        for path in comparison.forbidden_runtime_artifacts:
            print(f"FORBIDDEN_YARA_RUNTIME_ARTIFACT {path}")
    else:
        print("RELEASE_MANIFEST_GUARD_PASSED")
        for path in comparison.authorized_missing:
            print(f"AUTHORIZED_MISSING_SOURCE {path}")


def main(argv: tuple[str, ...] | None = None) -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path, help="Previous good release ZIP or source tree.")
    parser.add_argument("--candidate", required=True, type=Path, help="Candidate release ZIP or source tree.")
    args = parser.parse_args(argv)
    comparison = compare_release_manifests(args.baseline, args.candidate)
    _print_comparison(comparison)
    return 1 if comparison.release_blocked else 0


if __name__ == "__main__":
    raise SystemExit(main(tuple(sys.argv[1:])))
