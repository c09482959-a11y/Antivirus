import logging
import os
from pathlib import Path

from Virus_Scan.cli import args as cli_args
from Virus_Scan.core.logging import configure_single_parent_log
from Virus_Scan.orchestration.lifecycle import configure_parsed
from Virus_Scan.runtime.context import RuntimeContext


def _remove_file_handlers_for(path: Path):
    root = logging.getLogger()
    for handler in list(root.handlers):
        if isinstance(handler, logging.FileHandler) and Path(handler.baseFilename) == path:
            root.removeHandler(handler)
            handler.close()


def test_default_scanlog_is_in_generated_scan_logs_generation_and_can_be_disabled(tmp_path):
    parsed = cli_args.parse_args(["--dir", ".", "--scan-log-root", str(tmp_path / "Scan Logs")])
    configured = configure_parsed(RuntimeContext(), parsed)
    assert Path(configured.log).name == "scanlog"
    assert Path(configured.log).parent.parent.name == ".staging"
    assert Path(configured.log).parents[2].name == "Scan Logs"
    disabled = cli_args.parse_args(["--dir", ".", "--no-scanlog"])
    assert disabled.no_scanlog is True
    _remove_file_handlers_for(Path(configured.log).resolve())


def test_parent_log_truncates_at_scan_start(tmp_path):
    path = tmp_path / "Scan Logs" / ".staging" / "stage140" / "scanlog"
    path.parent.mkdir(parents=True)
    path.write_text("stale previous scan\n", encoding="utf-8")
    old_shard = os.environ.pop("UMIGE_PROCESS_SHARD", None)
    root = logging.getLogger()
    previous_level = root.level
    try:
        root.setLevel(logging.INFO)
        configured = configure_single_parent_log(str(path))
        assert configured == str(path.resolve())
        root.info("fresh scan marker")
        for handler in logging.getLogger().handlers:
            if isinstance(handler, logging.FileHandler) and Path(handler.baseFilename) == path.resolve():
                handler.flush()
        text = path.read_text(encoding="utf-8")
        assert "stale previous scan" not in text
        assert "fresh scan marker" in text
    finally:
        logging.getLogger().setLevel(previous_level)
        _remove_file_handlers_for(path.resolve())
        if old_shard is not None:
            os.environ["UMIGE_PROCESS_SHARD"] = old_shard
