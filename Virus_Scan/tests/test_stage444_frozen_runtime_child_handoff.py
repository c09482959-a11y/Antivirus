import sys

from Virus_Scan import main as startup_main
import build_entry_umige


def test_stage444_source_handoff_uses_runtime_module_process():
    command = startup_main._runtime_process_command_for_mode(("--dir", "sample"), compiled_process=False)
    assert command[:3] == (sys.executable, "-m", "Virus_Scan.runtime_main")
    assert command[3:] == ("--dir", "sample")


def test_stage444_frozen_handoff_uses_internal_runtime_child_token():
    command = startup_main._runtime_process_command_for_mode(("--dir", "sample"), compiled_process=True)
    assert command == (sys.executable, "--umige-runtime-child", "--dir", "sample")
    assert "-m" not in command


def test_stage444_runtime_handoff_rejects_non_boolean_compiled_mode():
    try:
        startup_main._runtime_process_command_for_mode(("--dir", "sample"), compiled_process=1)  # type: ignore[arg-type]
    except TypeError as exc:
        assert "compiled_process_must_be_bool" in str(exc)
    else:
        raise AssertionError("compiled mode accepted non-boolean value")


def test_stage444_build_entry_recognizes_internal_runtime_child_token():
    assert build_entry_umige._is_runtime_child(("--umige-runtime-child", "--dir", "sample"))
    assert not build_entry_umige._is_runtime_child(("--dir", "sample"))
