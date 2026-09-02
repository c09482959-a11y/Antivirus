"""Stage 690 detection Phase 6 continuation validation.

Ensures profile-selection confidence failures are not reduced to a clean
profile-selection fallback and are carried into final JSON/replay-visible
integrity fields.
"""
from __future__ import annotations

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from pathlib import Path

import pytest

from dataclasses import replace
from Virus_Scan.detection.orchestration.full_analysis.pipeline import (
    analyze_file_full_observe_only,
    default_full_analysis_pipeline_dependencies,
)
from Virus_Scan.detection.profiles import selection


def test_stage690_profile_confidence_failure_is_json_replay_visible(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "profile_failure.rpy"
    sample.write_text("init python:\n    import os\n    os.system('powershell -enc AAA')", encoding="utf-8")

    def fail_confidence(*_args, **_kwargs):
        raise RuntimeError("injected profile confidence failure")

    def profile_context_builder(**kwargs):
        return selection.build_detection_profile_context(
            **kwargs,
            engine_confidence_reporter=fail_confidence,
        )

    dependencies = replace(
        default_full_analysis_pipeline_dependencies(),
        profile_context_builder=profile_context_builder,
    )

    first = analyze_file_full_observe_only(
        sample,
        tags=["renpy_script", "powershell_exec"],
        dependencies=dependencies,
        scan_session_snapshot=scan_session_snapshot_fixture(),
        artifact_read_snapshot=artifact_read_snapshot_fixture(sample),
    )
    second = analyze_file_full_observe_only(
        sample,
        tags=["renpy_script", "powershell_exec"],
        dependencies=dependencies,
        scan_session_snapshot=scan_session_snapshot_fixture(),
        artifact_read_snapshot=artifact_read_snapshot_fixture(sample),
    )

    failures = first.get("detection_failures") or []
    assert any(item.get("stage_name") == "profile_engine_confidence" for item in failures)
    assert first.get("scan_integrity", {}).get("ok") is False
    assert first.get("scan_integrity", {}).get("json_record_required") is True
    assert first.get("scan_integrity", {}).get("replay_record_required") is True
    assert first.get("detection_profile_context", {}).get("engine_confidence", {}).get("degraded") is True
    assert first == second
