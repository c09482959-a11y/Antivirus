from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from Virus_Scan.orchestration import lifecycle
from Virus_Scan.runtime.api import get_deep_scan_mode
from Virus_Scan.storage import sqlite_lifecycle



class HostileValue:
    touched: list[str] = []

    @classmethod
    def reset(cls):
        cls.touched.clear()

    def __getattribute__(self, name):
        type(self).touched.append(str.__add__("__getattribute__:", name))
        raise AssertionError("caller-owned attribute lookup executed")

    def __str__(self):
        type(self).touched.append("__str__")
        return "hostile"

    def __repr__(self):
        type(self).touched.append("__repr__")
        return "hostile"

    def __format__(self, spec):
        type(self).touched.append("__format__")
        return "hostile"

    def __bool__(self):
        type(self).touched.append("__bool__")
        return True

    def __iter__(self):
        type(self).touched.append("__iter__")
        return iter(())

    def __hash__(self):
        type(self).touched.append("__hash__")
        return 1

    def __eq__(self, other):
        type(self).touched.append("__eq__")
        return False

    def __float__(self):
        type(self).touched.append("__float__")
        return 99.0

    def __int__(self):
        type(self).touched.append("__int__")
        return 99


class HostileArgs(HostileValue):
    output = "scan_results.json"
    log = "scan.log"
    vt_output = "vt.json"
    no_scanlog = False
    debug = False
    profile_corruption_policy = "hard-fail"
    deep_scan_mode = "thorough"
    dir = "."
    no_yara = False
    no_yaralight = False
    no_scan_cache = True
    yara_force_refresh = False
    scheduler = "serial"
    engine = "auto"
    preserve_virustotal_results = False
    preserve_scan_results = False
    no_stage_parallel = True
    stage_parallel_workers = 4
    stage_parallel_mode = "thread"
    workers = 1
    strict = False
    per_file_timeout = 1.0
    progress_every = 1
    throttle = 0.0
    max_files = None
    no_freeze_baseline = False
    flush_during_scan = False
    partial_output_every = 1
    slow_file_warn = 1.0
    file_list = None
    work_queue_dir = None
    worker_output = None
    yara = ""
    yara_no_download = True
    yara_config = None
    yara_release_api_url = None
    yara_status = False
    yara_no_cache = True
    yaralight_no_download = True


class RuntimeForConfigure:
    parent_cli = False
    scan_started_at = 0.0
    telemetry = {"owned": True}
    config = None

    def __init__(self):
        self.environment = SimpleNamespace(publish=lambda values: None, publish_defaults=lambda values: None)
        self.owner = SimpleNamespace(update=lambda values, domain=None: None)
        self.values = {"DEEP_SCAN_MODE": "auto", "SCAN_CACHE_ENABLED": False}

    def set(self, name, value):
        self.values[name] = value

    def get(self, name, default=None):
        return self.values.get(name, default)

    def has(self, name):
        return False


def _record(path="sample.bin"):
    return {
        "file": path,
        "path": path,
        "node": path,
        "score": 3.0,
        "classification": "benign_clean",
        "tags": ["media_asset", HostileValue()],
        "container_engine": "media",
        "artifact_engine": "media",
        "declared_extension": "bin",
        "sniffed_type": "png",
        "effective_analysis_engine": "media",
        "baseline_key": "media:bin",
        "extension_baseline": {},
        "contextual_baseline": {},
        "fingerprint_evidence": {},
        "sniffed_embedded_types": [HostileValue()],
        "detector_errors": [HostileValue()],
    }


def test_stage2022_configure_parsed_rejects_hostile_args_without_hooks(tmp_path: Path):
    args = HostileArgs()
    runtime = RuntimeForConfigure()
    saved = {
        "configure_single_parent_log": lifecycle.configure_single_parent_log,
        "configure_profile_corruption_policy": lifecycle.configure_profile_corruption_policy,
        "configure_runtime_engine_and_ilspy": lifecycle.configure_runtime_engine_and_ilspy,
        "ensure_authoritative_engine_profiles": lifecycle.ensure_authoritative_engine_profiles,
        "load_runtime_model_state": lifecycle.load_runtime_model_state,
    }
    HostileValue.reset()
    sqlite_lifecycle().configure(tmp_path / "profiles")

    def patched_noop_one(_value: object) -> None:
        return None

    def patched_identity(value: object) -> object:
        return value

    def patched_noop_zero() -> None:
        return None

    try:
        lifecycle.configure_single_parent_log = cast(Any, patched_noop_one)
        lifecycle.configure_profile_corruption_policy = cast(Any, patched_identity)
        lifecycle.configure_runtime_engine_and_ilspy = cast(Any, patched_noop_one)
        lifecycle.ensure_authoritative_engine_profiles = cast(Any, patched_noop_zero)
        lifecycle.load_runtime_model_state = cast(Any, patched_noop_zero)

        assert lifecycle.configure_parsed(runtime, args) is args
    finally:
        lifecycle.configure_single_parent_log = saved["configure_single_parent_log"]
        lifecycle.configure_profile_corruption_policy = saved["configure_profile_corruption_policy"]
        lifecycle.configure_runtime_engine_and_ilspy = saved["configure_runtime_engine_and_ilspy"]
        lifecycle.ensure_authoritative_engine_profiles = saved["ensure_authoritative_engine_profiles"]
        lifecycle.load_runtime_model_state = saved["load_runtime_model_state"]
        sqlite_lifecycle().close()

    assert HostileValue.touched == []
    assert get_deep_scan_mode() == "thorough"


def test_stage2022_orchestration_result_annotation_rejects_hostile_values_without_hooks():
    HostileValue.reset()

    annotated = lifecycle.attach_direct_audit_fields(HostileArgs(), {"sample.bin": _record()}, yara_ok=cast(bool, HostileValue()))

    assert annotated["sample.bin"]["detected_engine"] == "media"
    assert annotated["sample.bin"]["yara_enabled"] is False
    assert HostileValue.touched == []


def test_stage2022_prepare_and_run_scan_reject_hostile_args_without_hooks():
    args = HostileArgs()
    published = []
    runtime = SimpleNamespace(
        parent_cli=False,
        scan_started_at=0.0,
        environment=SimpleNamespace(publish=lambda values: published.append(values), publish_defaults=lambda values: None),
        owner=SimpleNamespace(update=lambda values, domain=None: None),
        config=None,
    )
    captured = {}

    def pipeline(scan_dir, **kwargs):
        captured["scan_dir"] = scan_dir
        captured.update(kwargs)
        return {"sample.bin": _record()}

    HostileValue.reset()
    lifecycle.prepare_scan(runtime, args)
    result = lifecycle.run_scan(args, compiled_rules=None, scheduler_pipeline=pipeline)

    assert result["sample.bin"]["file"] == "sample.bin"
    assert published[-1]["UMIGE_STAGE_PARALLEL_WORKERS"] == "4"
    assert captured["scheduler"] == "serial"
    assert captured["yara_enabled"] is False
    assert HostileValue.touched == []


def test_stage2022_lifecycle_source_has_no_repaired_hookable_patterns():
    source = read_python_file(Path("Virus_Scan/orchestration/lifecycle.py"))
    tree = ast.parse(source)

    assert [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
    assert "getattr(" not in source
    assert "hasattr(" not in source
    assert "(results or {}).items()" not in source
    assert "results.values()" not in source
