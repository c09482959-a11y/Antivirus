from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.contracts import library_baseline



class HostilePath:
    touched = 0

    def __fspath__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned fspath hook was invoked")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned text hook was invoked")


def test_stage2023_library_baseline_path_status_helpers_explain_unavailable_values() -> None:
    HostilePath.touched = 0

    assert library_baseline._path_parts_status(HostilePath()) == ((), "empty_path_text")
    assert library_baseline._path_name_status(HostilePath()) == ("", "empty_path_text")
    assert library_baseline._path_stem_suffix_parts_status(HostilePath()) == (None, "empty_path_name")
    assert HostilePath.touched == 0


def test_stage2023_library_baseline_probe_logger_uses_no_hook_type_name() -> None:
    messages: list[str] = []

    def bad_validation(_value):
        raise ValueError("broken")

    status, hard = library_baseline.library_baseline_hard_proof_status(
        tags=(),
        strings_blob="payload",
        validation_text=bad_validation,
        logger=messages.append,
    )

    assert (status, hard) == ("probe_error", True)
    assert messages == ["library baseline hard-proof text validation failed: ValueError"]


def test_stage2023_library_baseline_source_removed_backlog_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/contracts/library_baseline.py"))

    forbidden = (
        "except (OSError, RuntimeError, ValueError, TypeError, AttributeError):\n        return ()",
        "except (OSError, RuntimeError, ValueError, TypeError, AttributeError):\n        return \"\"",
        "except (OSError, RuntimeError, ValueError, TypeError, AttributeError):\n        return None",
        'logger(f"library baseline hard-proof text validation failed: {type(error).__name__}")',
    )
    for snippet in forbidden:
        assert snippet not in source
