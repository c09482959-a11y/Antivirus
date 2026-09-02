"""Release manifest guard regression tests."""
from __future__ import annotations

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from release_manifest_guard import (
    compare_release_manifests, forbidden_yara_runtime_artifacts_from_path,
)


def _write(path: Path, text: str = "# test\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _zip_tree(source: Path, target: Path) -> None:
    with ZipFile(target, "w", ZIP_DEFLATED) as zf:
        for path in source.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(source).as_posix())


def test_stage2276_release_manifest_guard_blocks_missing_scheduler_queue_source(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    _write(baseline / "Virus_Scan" / "scheduler" / "__init__.py")
    _write(baseline / "Virus_Scan" / "scheduler" / "queue" / "__init__.py")
    _write(baseline / "Virus_Scan" / "scheduler" / "queue" / "result_merge.py")
    _write(candidate / "Virus_Scan" / "scheduler" / "__init__.py")

    comparison = compare_release_manifests(baseline, candidate)

    assert comparison.release_blocked is True
    assert comparison.unauthorized_missing == (
        "Virus_Scan/scheduler/queue/__init__.py",
        "Virus_Scan/scheduler/queue/result_merge.py",
    )


def test_stage2276_release_manifest_guard_accepts_explicit_package_audit_authorization(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    _write(baseline / "Virus_Scan" / "scheduler" / "__init__.py")
    _write(baseline / "Virus_Scan" / "scheduler" / "queue" / "__init__.py")
    _write(baseline / "Virus_Scan" / "scheduler" / "queue" / "result_merge.py")
    _write(candidate / "Virus_Scan" / "scheduler" / "__init__.py")
    _write(
        candidate / "Audit" / "stage9999_authorized_source_deletion.md",
        "SOURCE_PACKAGE_DELETE_AUTHORIZED: Virus_Scan/scheduler/queue/\n",
    )

    comparison = compare_release_manifests(baseline, candidate)

    assert comparison.release_blocked is False
    assert comparison.authorized_missing == (
        "Virus_Scan/scheduler/queue/__init__.py",
        "Virus_Scan/scheduler/queue/result_merge.py",
    )


def test_stage2276_release_manifest_guard_compares_candidate_zip(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline_zip = tmp_path / "baseline.zip"
    candidate_zip = tmp_path / "candidate.zip"
    _write(baseline / "Virus_Scan" / "scheduler" / "__init__.py")
    _write(baseline / "Virus_Scan" / "scheduler" / "queue" / "__init__.py")
    _write(candidate / "Virus_Scan" / "scheduler" / "__init__.py")
    _zip_tree(baseline, baseline_zip)
    _zip_tree(candidate, candidate_zip)

    comparison = compare_release_manifests(baseline_zip, candidate_zip)

    assert comparison.release_blocked is True
    assert comparison.unauthorized_missing == ("Virus_Scan/scheduler/queue/__init__.py",)


def test_release_guard_allows_exact_yara_package_resources_and_rejects_runtime_state(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    _write(baseline / "Virus_Scan" / "__init__.py")
    _write(candidate / "Virus_Scan" / "__init__.py")
    for filename in (
        "README.md",
        "yara_defaults.toml",
        "yara_config.toml",
        "yara_config.schema.json",
        "yara_resource_manifest.json",
        "yara-forge-rules-core.zip",
        "yara-forge-rules-extended.zip",
    ):
        _write(candidate / "Yara" / filename, "package")
    _write(candidate / "Yara" / "yara.cache" / "groups" / "compiled-deadbeef.yarc", "cache")

    comparison = compare_release_manifests(baseline, candidate)

    assert comparison.release_blocked is True
    assert comparison.unauthorized_missing == ()
    assert comparison.forbidden_runtime_artifacts == (
        "Yara/yara.cache",
        "Yara/yara.cache/groups",
        "Yara/yara.cache/groups/compiled-deadbeef.yarc",
    )


def test_release_guard_allows_non_yara_generated_readmes_without_weakening_nested_yara_guard(tmp_path: Path) -> None:
    package = tmp_path / "controls.zip"
    with ZipFile(package, "w", ZIP_DEFLATED) as zf:
        zf.writestr("Yara/README.md", "yara controls")
        zf.writestr("Mitre/README.md", "mitre controls")
        zf.writestr("VirusTotal/README.md", "virustotal controls")
        zf.writestr("Audit/report.md", "audit")
        zf.writestr("Audit/evidence/Yara/README.md", "misplaced yara control")
        zf.writestr("Audit/evidence/yara_config.toml", "misplaced yara config")

    assert forbidden_yara_runtime_artifacts_from_path(package) == (
        "Audit/evidence/Yara/README.md",
        "Audit/evidence/yara_config.toml",
    )


def test_release_guard_rejects_yara_runtime_artifacts_inside_audit_zip(tmp_path: Path) -> None:
    package = tmp_path / "audit.zip"
    with ZipFile(package, "w", ZIP_DEFLATED) as zf:
        zf.writestr("Audit/report.md", "report")
        zf.writestr("Audit/evidence/yaralight.cache/compiled-deadbeef.yarc", b"cache")
        zf.writestr("Audit/evidence/yara_extended_state.json", b"{}")
        zf.writestr("Audit/evidence/.umige-yara.lock", b"")

    forbidden = forbidden_yara_runtime_artifacts_from_path(package)

    assert forbidden == (
        "Audit/evidence/.umige-yara.lock",
        "Audit/evidence/yara_extended_state.json",
        "Audit/evidence/yaralight.cache/compiled-deadbeef.yarc",
    )


def test_release_guard_rejects_nested_runtime_yara_directory_but_allows_source_owners(tmp_path: Path) -> None:
    package = tmp_path / "audit.zip"
    with ZipFile(package, "w", ZIP_DEFLATED) as zf:
        zf.writestr("Audit/evidence/Yara/random.bin", b"runtime")
        zf.writestr("Virus_Scan/yara/source.py", b"# canonical source owner\n")
        zf.writestr("Virus_Scan/detection/scoring/yara/policy.py", b"# canonical scoring owner\n")
        zf.writestr("Virus_Scan/yara/Yara/runtime.bin", b"runtime")
        zf.writestr("Virus_Scan/detection/scoring/yara/Yara/runtime.bin", b"runtime")

    assert forbidden_yara_runtime_artifacts_from_path(package) == (
        "Audit/evidence/Yara/random.bin",
        "Virus_Scan/detection/scoring/yara/Yara/runtime.bin",
        "Virus_Scan/yara/Yara/runtime.bin",
    )
