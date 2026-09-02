from Virus_Scan.cli.args import parse_args


def test_stage404_pasted_corpus_command_flags_parse_to_canonical_fields(tmp_path):
    args = parse_args([
        "--dir", str(tmp_path),
        "--scheduler", "serial",
        "--deep-scan", "auto",
        "--profile", "renpy",
        "--no-yara",
    ])
    assert args.engine == "renpy"
    assert args.deep_scan_mode == "auto"
    assert args.scheduler == "serial"


def test_stage404_existing_engine_and_deep_scan_mode_flags_remain_canonical(tmp_path):
    args = parse_args([
        "--dir", str(tmp_path),
        "--scheduler", "process",
        "--workers", "2",
        "--deep-scan-mode", "thorough",
        "--engine", "unity",
    ])
    assert args.engine == "unity"
    assert args.deep_scan_mode == "thorough"
    assert args.scheduler == "process"
    assert args.workers == 2
