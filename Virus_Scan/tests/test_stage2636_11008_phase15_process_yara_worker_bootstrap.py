"""Phase 15 spawned-worker bootstrap for the canonical YARA runtime."""
from __future__ import annotations

from argparse import Namespace
import os
from pathlib import Path

import pytest

pytest.importorskip("yara")

from Virus_Scan.orchestration.scan_session import build_scan_session_snapshot
from Virus_Scan.routing.scanner_execution_plan import scanner_execution_capability_registry_digest
from Virus_Scan.orchestration.yara_initialization import initialize_yara_from_args
from Virus_Scan.runtime.api import RuntimeContext, configure_deep_scan_mode, release_yara_runtime
from Virus_Scan.orchestration.worker_runtime_descriptors import (
    build_worker_yara_runtime_descriptor,
)
from Virus_Scan.scheduler.runtime.multiprocessing_context import (
    get_scheduler_multiprocessing_context,
)
from Virus_Scan.scheduler.workers.inmemory_worker_bootstrap_steps import (
    configure_worker_yara_runtime,
)
from Virus_Scan.storage import authoritative_model_state, scan_cache_repository
from Virus_Scan.yara.config import config_toml
from Virus_Scan.yara.match import yara_scan

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_CORE_ARCHIVE = _REPOSITORY_ROOT / "Yara" / "yara-forge-rules-core.zip"
_CORE_SHA256 = "3ad85d8518e5e968d930c93dadae9dcd7d215d0911d8d8f02717f15922c8529f"
_EXPECTED_RULE = "DITEKSHEN_INDICATOR_TOOL_PWS_LSASS_Createminidump"
_FIXTURE = (
    b"MZ" + b"\x00" * 62
    + b"lsass dumped successfully!\x00Got lsass.exe PID:\x00SAFE INERT FIXTURE\n"
)


def _worker_probe(descriptor: object, fixture_path: str, result_queue: object) -> None:
    try:
        snapshot = configure_worker_yara_runtime({"yara_runtime_descriptor": descriptor})
        result = yara_scan(Path(fixture_path), compiled_rules=snapshot)
        result_queue.put({
            "status": result.status,
            "package_kind": result.package_kind,
            "rule_names": tuple(hit.rule_identity.rule_name for hit in result.hits),
            "unavailable_reason": result.unavailable_reason,
        })
    except BaseException as exc:  # process boundary must publish exact failure type
        result_queue.put({"error_type": type(exc).__name__, "error_text": str(exc)})
    finally:
        release_yara_runtime()


def test_spawned_worker_rebuilds_parent_approved_core_runtime(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    fixture_path = tmp_path / "lsass.pe.fixture"
    fixture_path.write_bytes(_FIXTURE)
    previous_base_dir = os.environ.get("UMIGE_BASE_DIR")
    os.environ["UMIGE_BASE_DIR"] = str(runtime_root)
    release_yara_runtime()
    configure_deep_scan_mode("fast")
    try:
        yara_root = runtime_root / "Yara"
        yara_root.mkdir(parents=True, exist_ok=True)
        config_path = yara_root / "yara_config.toml"
        config_path.write_text(
            config_toml().replace(
                'light_expected_sha256 = ""',
                f'light_expected_sha256 = "{_CORE_SHA256}"',
            ),
            encoding="utf-8",
        )
        compiled, ready = initialize_yara_from_args(
            RuntimeContext(),
            Namespace(
                no_yara=False,
                no_yaralight=False,
                scheduler="serial",
                deep_scan_mode="fast",
                yara=None,
                yaralight=str(_CORE_ARCHIVE),
                yara_config=str(config_path),
                yara_force_refresh=False,
                yara_no_download=True,
                yaralight_no_download=True,
                yara_release_api_url=None,
                yara_no_cache=True,
                yara_status=False,
            ),
        )
        assert ready is True
        assert compiled is not None
        profiles_dir = runtime_root / "profiles"
        authoritative_model_state().configure(profiles_dir)
        scan_cache_repository().configure(profiles_dir, enabled=False)
        session = build_scan_session_snapshot(
            compiled_rules=compiled, yara_enabled=True, scan_mode="process", worker_count=1,
        )
        assert session.scanner_registry_state == "available"
        assert session.scanner_registry_digest == scanner_execution_capability_registry_digest()
        assert session.scanner_registry_reason == ""
        assert any(
            item.name == "scanner_applicability"
            and item.state == "available"
            and item.identity_digest == session.scanner_registry_digest
            for item in session.subsystem_states
        )
        descriptor = build_worker_yara_runtime_descriptor(session)
        release_yara_runtime()

        context = get_scheduler_multiprocessing_context(preferred="spawn")
        result_queue = context.Queue()
        process = context.Process(
            target=_worker_probe,
            args=(descriptor, str(fixture_path), result_queue),
        )
        process.start()
        process.join(120)
        assert process.exitcode == 0
        record = result_queue.get(timeout=10)
        assert record == {
            "status": "complete",
            "package_kind": "core",
            "rule_names": (_EXPECTED_RULE,),
            "unavailable_reason": "",
        }
    finally:
        release_yara_runtime()
        configure_deep_scan_mode("auto")
        if previous_base_dir is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous_base_dir
