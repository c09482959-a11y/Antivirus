"""Stage2636.11020 Phase 8 canonical worker-launcher regression tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


def test_direct_api_client_cannot_become_process_queue_launcher(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[2]
    client = tmp_path / "embedded_client.py"
    client.write_text(
        "from Virus_Scan.scheduler.ownership.scheduler_identity import build_scheduler_process_identity\n"
        "import json\n"
        "identity = build_scheduler_process_identity()\n"
        "print(json.dumps({'script_path': str(identity.script_path), 'python_executable': identity.python_executable}, sort_keys=True))\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repository_root)
    completed = subprocess.run(
        (sys.executable, str(client)),
        cwd=tmp_path,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    identity = json.loads(completed.stdout)
    assert Path(identity["script_path"]) == (repository_root / "build_entry_umige.py").resolve()
    assert Path(identity["script_path"]) != client.resolve()
    assert Path(identity["python_executable"]).resolve() == Path(sys.executable).resolve()


def test_direct_scheduler_api_enters_canonical_runtime_bootstrap(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[2]
    base = tmp_path / "runtime"
    corpus = base / "corpus"
    corpus.mkdir(parents=True)
    (corpus / "sample.txt").write_text("direct scheduler bootstrap\n", encoding="utf-8")
    client = tmp_path / "direct_scheduler_client.py"
    client.write_text(
        "from Virus_Scan.scheduler.api.runner import run_pipeline_safe\n"
        "import json, os\n"
        "from pathlib import Path\n"
        "corpus = Path(os.environ['DIRECT_CORPUS']).resolve()\n"
        "results = run_pipeline_safe(str(corpus), scheduler='serial', max_workers=1, yara_enabled=False, freeze_existing_baselines=False)\n"
        "print(json.dumps({'count': len(results), 'paths': sorted(results)}, sort_keys=True))\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env.update(
        {
            "PYTHONPATH": str(repository_root),
            "UMIGE_BASE_DIR": str(base),
            "DIRECT_CORPUS": str(corpus),
            "UMIGE_NO_YARA": "1",
            "UMIGE_NO_YARALIGHT": "1",
            "UMIGE_NO_MITRE": "1",
        }
    )
    completed = subprocess.run(
        (sys.executable, str(client)),
        cwd=tmp_path,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    assert "ClusterStateNotConfigured" not in completed.stderr
    result = json.loads(completed.stdout.splitlines()[-1])
    assert result["count"] == 1
    assert result["paths"] == [str((corpus / "sample.txt").resolve())]


def test_compact_publication_preserves_scan_session_lineage() -> None:
    from Virus_Scan.publication.json_finalization.success_fields import compact_success_scheduler_fields

    session = {
        "schema_version": "scan_session_snapshot_v3",
        "generation_id": "a" * 64,
        "scan_mode": "auto",
        "configuration_digest": "b" * 64,
        "model_state_digest": "c" * 64,
        "cache_execution_identity_digest": "d" * 64,
    }
    fields = compact_success_scheduler_fields(
        {"scheduler_mode": "process-fs", "scan_session": session},
        {
            "scan_duration_seconds": 0.0,
            "serial_execution_marker": None,
            "tags": (),
        },
    )
    assert fields["scan_session"] == session
