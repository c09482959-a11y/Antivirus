"""Bounded builders for the canonical UMIGE CLI parser."""

import argparse

from Virus_Scan.contracts.env_config import int_env, str_env


def build_parser() -> argparse.ArgumentParser:
    """Build the canonical UMIGE CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="umige",
        description="UMIGE staged malware analysis engine",
    )
    add_target_options(parser)
    add_yara_options(parser)
    add_mitre_options(parser)
    add_output_options(parser)
    add_runtime_options(parser)
    add_scheduler_options(parser)
    add_engine_tool_options(parser)
    add_safety_profile_options(parser)
    return parser


def add_target_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--version", action="version", version="UMIGE")
    parser.add_argument("--dir", required=True, help="File or directory to scan.")


def add_yara_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--yara",
        help="Explicit heavy YARA .yar/.yara file or rules .zip. Overrides YARA Forge extended auto-resolution.",
        default=None,
    )
    parser.add_argument(
        "--yaralight",
        help="Explicit YARA-light .yar/.yara file or core rules .zip. Overrides YARA Forge core auto-resolution.",
        default=None,
    )
    parser.add_argument("--no-yara", action="store_true", help="Disable YARA loading/scanning entirely.")
    parser.add_argument(
        "--yara-no-download",
        action="store_true",
        help="Do not download YARA Forge extended rules; only use --yara or a validated local extended archive/rule file.",
    )
    parser.add_argument(
        "--yara-force-refresh",
        action="store_true",
        help="Force refresh of the YARA Forge package selected by scan mode, bypassing freshness cooldown and conditional cache headers.",
    )
    parser.add_argument("--yara-config", default=None, help="Explicitly load the validated Yara/yara_config.toml file.")
    parser.add_argument("--yara-status", action="store_true", help="Log YARA integrity, compilation, cache, and lock status at startup.")
    parser.add_argument("--yara-no-cache", action="store_true", help="Disable compiled YARA cache in ./Yara/yara.cache and compile rules fresh.")
    parser.add_argument("--no-yaralight", action="store_true", help="Disable YARA Forge core rule execution in fast scan mode.")
    parser.add_argument("--yaralight-no-download", action="store_true", help="Do not download YARA Forge core rules for fast scans; only use --yaralight or a validated local core archive/rule file.")


def add_mitre_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--no-mitre", action="store_true", help="Disable official Enterprise ATT&CK repository loading and mapping.")
    parser.add_argument("--mitre-config", default=None, help="Explicitly load and validate the canonical Mitre/mitre_config.toml override; normal startup uses typed defaults without reading the file.")
    parser.add_argument("--mitre-no-download", action="store_true", help="Use only the validated persistent local Mitre cache.")
    parser.add_argument("--mitre-force-refresh", action="store_true", help="Refresh Enterprise ATT&CK through the GitHub Contents API identity path.")
    parser.add_argument("--mitre-api-url", default=None, help="Validated GitHub Contents API URL override for enterprise-attack.json.")
    parser.add_argument("--mitre-ref", default=None, help="Bounded Git repository ref override for ATT&CK refresh.")
    parser.add_argument("--mitre-status", action="store_true", help="Log ATT&CK repository integrity and availability status at startup.")


def add_output_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--scan-log-root",
        default=None,
        help="Canonical Scan Logs root. Each scan writes into one generated .staging/<scan_id> generation.",
    )
    parser.add_argument("--scan-id", default=None, help=argparse.SUPPRESS)
    parser.add_argument(
        "--no-scanlog",
        action="store_true",
        help="Disable the parent-owned scanlog while retaining the canonical Scan Logs generation.",
    )
    parser.add_argument(
        "--preserve-scan-results",
        action="store_true",
        help=argparse.SUPPRESS,
    )


def add_runtime_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--partial-output-every", type=int, default=10, help="Write output.partial every N files so long scans preserve progress; use 0 to disable periodic partial writes.")
    parser.add_argument("--slow-file-warn", type=float, default=2.0, help="Log SLOW FILE when a handler exceeds this many seconds. Use 0 to disable.")
    parser.add_argument(
        "--deep-scan-mode",
        "--deep-scan",
        dest="deep_scan_mode",
        choices=["auto", "balanced", "thorough", "fast"],
        default=str_env("UMIGE_DEEP_SCAN_MODE", "auto"),
        help="Deep-scan policy. auto is default: balanced triage first, then thorough enrichment/YARA/full observe only for escalated files. thorough forces exhaustive scanning everywhere; balanced keeps passive assets cheap.",
    )
    parser.add_argument("--workers", type=int, default=0, help="Total worker budget. 0=auto based on CPU. Use 1 or --scheduler serial for deterministic single-lane scanning.")
    parser.add_argument("--resource-priority", "--priority", choices=["high", "medium", "low"], default=str_env("UMIGE_RESOURCE_PRIORITY", "high").strip().lower(), help="Resource profile for queue scheduling and raw-stage backpressure. high=highest safely aggressive and default; medium=balanced; low=reduced machine impact.")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--per-file-timeout", type=int, default=20, help="Maximum seconds allowed per file before returning a timeout record. Use 0 to disable.")
    parser.add_argument("--progress-every", type=int, default=10, help="Log bulk scan progress every N files.")
    parser.add_argument("--throttle", type=float, default=0.0, help="Sleep this many seconds after each file to reduce resource pressure.")
    parser.add_argument("--max-files", type=int, default=None, help="Optional cap on files scanned from the target after deterministic collection.")


def add_scheduler_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scheduler", choices=["process", "process-fs", "serial", "queue-child"], default="process", help="Bulk scheduling mode. process is the default long-lived process-owned scheduler; process-fs uses the durable filesystem queue with isolated queue children; serial is deterministic single-process mode; queue-child is the isolated internal queue worker mode.")
    parser.add_argument("--no-stage-parallel", action="store_true", help="Disable per-file stage-parallel collectors. Process workers still run normally.")
    parser.add_argument("--stage-parallel-workers", type=int, default=int_env("UMIGE_STAGE_PARALLEL_WORKERS", 6, 1, None), help="Collector workers inside each heavy file route. Default 6. Use 2-4 with many process workers; 8-16 for one huge file.")
    parser.add_argument("--stage-parallel-mode", choices=["thread", "process", "auto"], default=str_env("UMIGE_STAGE_PARALLEL_MODE", "thread"), help="Backend for per-file stage collectors. thread=safest; process=real CPU parallelism for one huge file; auto=process in queue children.")
    parser.add_argument("--work-queue-dir", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--worker-output", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--scan-session-manifest", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--file-list", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--no-freeze-baseline", action="store_true", help="Disable bulk scoring snapshot. By default, scans use only profile data that existed before the batch.")
    parser.add_argument("--flush-during-scan", action="store_true", help="Commit authoritative profile/model state during the scan instead of keeping bulk updates in memory until finalization.")


def add_engine_tool_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--engine", "--profile", dest="engine", choices=["auto", "unity", "renpy", "rpgm", "media", "other"], default="auto", help="Default engine/profile hint for the scan. Detection can override this when target evidence is strong.")
    parser.add_argument("--ilspy", nargs="?", const="auto", default=None, help="Enable ILSpy for .NET .exe/.dll files after a CLR precheck. Optional executable path accepted; otherwise ilspycmd.exe is looked up beside this script. Use --path to override.")
    parser.add_argument("--path", dest="ilspy_path", default=None, help="Override ILSpy executable path. Default when --ilspy is enabled: ilspycmd.exe beside this script.")
    parser.add_argument("--dump", dest="ilspy_dump", default=None, help="Override ILSpy dump directory. Default remains one level above the scanned folder in a dump directory.")
    parser.add_argument("--ilspy-timeout", type=int, default=60, help="Maximum seconds per ILSpy decompile before falling back to AST/static scanning.")


def add_safety_profile_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--strict", action="store_true", help="Raise worker exceptions instead of returning error records.")
    parser.add_argument("--no-scan-cache", action="store_true", help="Disable persistent SHA-256 pre-scan cache in profiles/scan_cache.sqlite3.")
    parser.add_argument(
        "--profile-corruption-policy",
        choices=["hard-fail", "quarantine"],
        default="hard-fail",
        help="Profile schema corruption policy. Default hard-fails with a clear error; quarantine explicitly preserves the corrupt profile and continues.",
    )
