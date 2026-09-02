"""Stage2636.11004 canonical explicit YARA-light source integration."""
from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from Virus_Scan.cli.arg_parser_builders import build_parser
from Virus_Scan.cli.args import parse_args
from Virus_Scan.orchestration import lifecycle
from Virus_Scan.orchestration.yara_initialization import initialize_yara_from_args
from Virus_Scan.runtime.api import RuntimeContext
from Virus_Scan.storage import sqlite_lifecycle
from Virus_Scan.scheduler.workers.spawn import (
    ProcessQueueWorkerSpawnRequest,
    build_process_queue_worker_command,
)
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.contracts import YaraRuleLoadResult
from Virus_Scan.yara.loader import YaraLoadAttempt, load_yaralight_rules


def _unready(reason: str = "fixture") -> YaraLoadAttempt:
    return YaraLoadAttempt(
        None,
        None,
        None,
        YaraRuleLoadResult(
            state="integrity_failure",
            ready=False,
            total_members=0,
            compiled_members=0,
            failed_members=0,
            acceptance_threshold=0.95,
            failure_samples=(),
            reason=reason,
        ),
        False,
    )


def _spawn_request(tmp_path: Path, env: dict[str, str]) -> ProcessQueueWorkerSpawnRequest:
    return ProcessQueueWorkerSpawnRequest(
        root=tmp_path / "target",
        queue_dir=tmp_path / "queue",
        output=tmp_path / "out.json",
        worker_index=0,
        script_path=tmp_path / "entry.py",
        python_executable="python",
        env_base=env,
        progress_every=10,
        partial_output_every=0,
        slow_file_warn_sec=0.0,
        per_file_timeout_sec=60,
        throttle_sec=0.0,
        strict=True,
        scan_session_manifest_path=tmp_path / "scan_session_snapshot.json",
    )


def test_cli_accepts_explicit_heavy_and_light_rule_archives() -> None:
    args = parse_args([
        "--dir", ".",
        "--yara", "D:/Yara/yara-forge-rules-extended.zip",
        "--yaralight", "D:/Yara/yara-forge-rules-core.zip",
        "--yaralight-no-download",
    ])
    assert args.yara == "D:/Yara/yara-forge-rules-extended.zip"
    assert args.yaralight == "D:/Yara/yara-forge-rules-core.zip"
    assert args.yaralight_no_download is True


def test_cli_help_describes_mode_selected_yara_packages() -> None:
    help_text = " ".join(build_parser().format_help().split())
    assert "selected by scan mode" in help_text
    assert "core rule execution in fast scan mode" in help_text
    assert "core rules for fast scans" in help_text
    assert "bypass prescan" not in help_text


def test_light_loader_resolves_explicit_path_through_canonical_source_owner() -> None:
    captured: dict[str, object] = {}

    def resolve(package: str, **kwargs: object) -> None:
        captured["package"] = package
        captured.update(kwargs)
        return None

    with patch("Virus_Scan.yara.loader.resolve_rule_source", resolve):
        attempt = load_yaralight_rules(
            "D:/Yara/yara-forge-rules-core.zip",
            auto_download=False,
            use_cache=False,
            config=YaraConfig(),
        )

    assert attempt.load_result.reason == "yaralight_rule_source_unavailable"
    assert captured["package"] == "core"
    assert captured["explicit_path"] == "D:/Yara/yara-forge-rules-core.zip"
    assert captured["auto_download"] is False


def test_initializer_passes_explicit_light_path_to_existing_loader(tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def load_light(*, rule_path: object = None, **kwargs: object) -> YaraLoadAttempt:
        captured["rule_path"] = rule_path
        captured.update(kwargs)
        return _unready("light_fixture")

    args = Namespace(
        no_yara=False,
        no_yaralight=False,
        scheduler="serial",
        deep_scan_mode="fast",
        yara=None,
        yaralight=str(tmp_path / "core.zip"),
        yara_config=None,
        yara_force_refresh=False,
        yara_no_download=True,
        yaralight_no_download=True,
        yara_release_api_url=None,
        yara_no_cache=True,
        yara_status=False,
    )
    runtime = RuntimeContext()
    with (
        patch("Virus_Scan.orchestration.yara_initialization.yara_dir", lambda: str(tmp_path / "Yara")),
        patch("Virus_Scan.orchestration.yara_initialization.yara_loader.load_yara_rules", lambda **_kwargs: _unready("full_fixture")),
        patch("Virus_Scan.orchestration.yara_initialization.yara_loader.load_yaralight_rules", load_light),
    ):
        _compiled, ready = initialize_yara_from_args(runtime, args)

    assert ready is False
    assert captured["rule_path"] == str(tmp_path / "core.zip")
    assert captured["auto_download"] is False


def test_queue_child_preserves_explicit_heavy_and_light_sources(tmp_path: Path) -> None:
    heavy = str(tmp_path / "Yara" / "extended.zip")
    light = str(tmp_path / "Yara" / "core.zip")
    command = build_process_queue_worker_command(_spawn_request(tmp_path, {
        "UMIGE_DEEP_SCAN_MODE": "thorough",
        "UMIGE_YARA_RULE_PATH": heavy,
        "UMIGE_YARALIGHT_RULE_PATH": light,
    }))

    assert command[command.index("--yara") + 1] == heavy
    assert command[command.index("--yaralight") + 1] == light
    assert "--yara-no-download" in command
    assert "--yaralight-no-download" in command


def test_queue_child_rejects_hostile_explicit_source_without_calling_hooks(tmp_path: Path) -> None:
    class HostilePath:
        touched = False

        def __fspath__(self):  # pragma: no cover - failure proves unsafe conversion
            type(self).touched = True
            raise AssertionError("hook executed")

        def __str__(self):  # pragma: no cover
            type(self).touched = True
            raise AssertionError("hook executed")

    request = _spawn_request(tmp_path, {"UMIGE_YARALIGHT_RULE_PATH": HostilePath()})
    command = build_process_queue_worker_command(request)

    assert command[command.index("--yaralight") + 1] == "<rejected-UMIGE_YARALIGHT_RULE_PATH>"
    assert HostilePath.touched is False


class _ConfigureRuntime:
    parent_cli = False

    def __init__(self) -> None:
        self.values = {"DEEP_SCAN_MODE": "auto", "SCAN_CACHE_ENABLED": False}
        self.published: list[dict[str, object]] = []
        self.environment = SimpleNamespace(
            publish=lambda values: self.published.append(dict(values)),
            is_process_shard=lambda: False,
        )

    def set(self, name: str, value: object) -> None:
        self.values[name] = value

    def get(self, name: str, default: object = None) -> object:
        return self.values.get(name, default)

    def has(self, _name: str) -> bool:
        return False


def test_runtime_publishes_explicit_sources_for_process_workers(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    heavy = str(tmp_path / "extended.zip")
    light = str(tmp_path / "core.zip")
    args = parse_args([
        "--dir", str(target),
        "--yara", heavy,
        "--yaralight", light,
        "--no-scan-cache",
    ])
    runtime = _ConfigureRuntime()
    sqlite_lifecycle().configure(tmp_path / "profiles")
    with (
        patch.object(lifecycle, "configure_single_parent_log", lambda _value: None),
        patch.object(lifecycle, "configure_profile_corruption_policy", lambda value: value),
        patch.object(lifecycle, "configure_runtime_engine_and_ilspy", lambda _args: None),
        patch.object(lifecycle, "ensure_authoritative_engine_profiles", lambda: None),
        patch.object(lifecycle, "load_runtime_model_state", lambda: None),
    ):
        lifecycle.configure_parsed(runtime, args)

    published = {}
    for values in runtime.published:
        published.update(values)
    assert published["UMIGE_YARA_RULE_PATH"] == heavy
    assert published["UMIGE_YARALIGHT_RULE_PATH"] == light
