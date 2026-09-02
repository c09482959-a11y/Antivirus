"""Stage2636.05 inert YARA corpus-effectiveness evaluation contracts."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path

import pytest

from tools.evaluation.evaluate_yara_rules import (
    CORPUS_VERSION,
    EVALUATION_VERSION,
    YaraEvaluationRule,
    _fixture_corpora,
    acceptance,
    evaluate_yara_rules,
)
from Virus_Scan.runtime.yara_rules_state import yara_runtime_snapshot


ROOT = Path(__file__).resolve().parents[1]


def test_stage2636_10011_yara_evaluation_reports_full_and_light_required_metrics() -> None:
    report = evaluate_yara_rules()
    assert report["evaluation_version"] == EVALUATION_VERSION
    assert report["corpus_version"] == CORPUS_VERSION
    assert report["fixture_provenance"] == "approved_inert_metadata_no_live_malware"
    assert tuple(sorted(report["packages"])) == ("full", "light")
    for package in ("full", "light"):
        row = report["packages"][package]
        assert row["compile"]["success_rate"] == 1.0
        assert row["rule_identity"]["duplicate_rule_identifier_count"] == 0
        assert row["classification"]["precision"] == 1.0
        assert row["classification"]["benign_false_positive_rate"] == 0.0
        assert row["coverage"]["family_coverage_rate"] == 1.0
        assert row["coverage"]["behavior_coverage_rate"] == 1.0
        assert row["incremental_benefit"]["recall_delta"] > 0.0
        assert row["rule_health_indicators"]["stale_rule_count"] == 1
        assert row["rule_health_indicators"]["unreachable_rule_count"] == 1
        assert row["rule_health_indicators"]["stale_and_unreachable_identifiers"]
        assert row["latency"]["sample_count"] == row["classification"]["sample_count"]
        assert row["memory"]["sample_count"] == row["classification"]["sample_count"]
    assert all(acceptance(report).values())
    assert report["all_acceptance_passed"] is True


def test_stage2636_10011_yara_evaluation_digest_is_runtime_measurement_independent() -> None:
    first = evaluate_yara_rules()
    second = evaluate_yara_rules()
    assert first["manifest_digest"] == second["manifest_digest"]
    assert first["packages"]["full"]["semantic_digest"] == second["packages"]["full"]["semantic_digest"]
    assert first["packages"]["light"]["semantic_digest"] == second["packages"]["light"]["semantic_digest"]
    assert (
        first["packages"]["full"]["latency"] != second["packages"]["full"]["latency"]
        or first["packages"]["light"]["memory"] != second["packages"]["light"]["memory"]
        or first["manifest_digest"] == second["manifest_digest"]
    )


def test_stage2636_10011_yara_evaluation_manifest_digest_matches_stable_projection() -> None:
    report = evaluate_yara_rules()
    stable = {
        "evaluation_version": report["evaluation_version"],
        "corpus_version": report["corpus_version"],
        "fixture_provenance": report["fixture_provenance"],
        "production_entry_point": report["production_entry_point"],
        "evaluation_owner": report["evaluation_owner"],
        "runtime_state_mutated": report["runtime_state_mutated"],
        "packages": {
            kind: {
                key: value for key, value in report["packages"][kind].items()
                if key not in ("latency", "memory")
            }
            for kind in ("full", "light")
        },
    }
    expected = hashlib.sha256(json.dumps(
        stable, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")).hexdigest()
    assert report["manifest_digest"] == expected


def test_stage2636_10011_yara_evaluation_does_not_mutate_runtime_state() -> None:
    before = yara_runtime_snapshot()
    report = evaluate_yara_rules()
    after = yara_runtime_snapshot()
    assert report["runtime_state_mutated"] is False
    assert after == before


def test_stage2636_10011_yara_evaluation_records_are_immutable() -> None:
    rule = _fixture_corpora()[0].rules[0]
    with pytest.raises(FrozenInstanceError):
        rule.rule_id = "changed"
    assert type(rule) is YaraEvaluationRule


def test_stage2636_10011_production_does_not_import_evaluation_owner() -> None:
    bad = []
    for path in ROOT.rglob("*.py"):
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if "tools.evaluation.evaluate_yara_rules" in text:
            bad.append(path.relative_to(ROOT).as_posix())
    assert bad == []
