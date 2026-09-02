from Virus_Scan.cli.args import normalize_runtime_args, parse_args
from Virus_Scan.yara import loader


def test_partial_output_every_restored_to_v27c_default():
    args = normalize_runtime_args(parse_args(["--dir", "."]))
    assert args.partial_output_every == 10


def test_partial_output_every_zero_remains_explicit_disable():
    args = normalize_runtime_args(parse_args(["--dir", ".", "--partial-output-every", "0"]))
    assert args.partial_output_every == 0


def test_yara_loading_has_no_parallel_cli_parser():
    assert not hasattr(loader, "parse_args")
