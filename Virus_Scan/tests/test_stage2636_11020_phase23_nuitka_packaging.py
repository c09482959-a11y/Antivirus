"""Phase 23 packaged parser-runtime Nuitka configuration regressions."""
from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path

from nuitka.utils.Yaml import getYamlPackage


_SCANNER_CONFIG_DATA_PATTERNS = (
    "defaults/archive_policy.json",
    "defaults/binary_policy.json",
    "defaults/engine_policy.json",
    "defaults/filetype_policy.json",
    "defaults/payload_policy.json",
    "defaults/pickle_policy.json",
    "defaults/raw_chunk_policy.json",
    "defaults/scanner_limits_policy.json",
    "defaults/text_policy.json",
    "schemas/archive_policy.schema.json",
    "schemas/binary_policy.schema.json",
    "schemas/engine_policy.schema.json",
    "schemas/filetype_policy.schema.json",
    "schemas/payload_policy.schema.json",
    "schemas/pickle_policy.schema.json",
    "schemas/raw_chunk_policy.schema.json",
    "schemas/scanner_limits_policy.schema.json",
    "schemas/text_policy.schema.json",
)


_DATA_PATTERNS = (
    "typescript_parser_bridge.js",
    "typescript_parser_resource/typescript.js",
    "typescript_parser_resource/LICENSE.txt",
    "typescript_parser_resource/ThirdPartyNoticeText.txt",
    "typescript_parser_resource/package.json",
    "typescript_parser_resource/node_runtime_manifest.json",
    "typescript_parser_resource/node_runtime/NODE_LICENSE.txt",
    "typescript_parser_resource/node_runtime/SHASUMS256.txt",
)


def _configuration() -> tuple[Path, dict[str, dict[str, object]]]:
    root = Path(__file__).resolve().parents[2]
    path = root / "umige.nuitka-package.config.yml"
    value = getYamlPackage().safe_load(path.read_text(encoding="utf-8"))
    assert type(value) is list and len(value) == 3
    records: dict[str, dict[str, object]] = {}
    for record in value:
        assert type(record) is dict
        module_name = record.get("module-name")
        assert type(module_name) is str and module_name not in records
        records[module_name] = record
    assert set(records) == {
        "Virus_Scan.scanners.config",
        "Virus_Scan.scanners.static_program_analysis",
        "packaged_capstone_5_0_9",
    }
    return root, records


def test_phase23_nuitka_build_entry_owns_one_package_configuration() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (root / "build_entry_umige.py").read_text(encoding="utf-8")
    configuration_directive = (
        "# nuitka-project: --user-package-configuration-file="
        "{MAIN_DIRECTORY}/umige.nuitka-package.config.yml"
    )
    finalizer_directive = (
        "# nuitka-project: --user-plugin="
        "{MAIN_DIRECTORY}/tools/nuitka_packaging/exact_runtime_plugin.py"
    )

    assert source.count(configuration_directive) == 1
    assert source.count(finalizer_directive) == 1
    future_index = source.index("from __future__ import annotations")
    assert source.index(configuration_directive) < future_index
    assert source.index(finalizer_directive) < future_index


def test_phase23_nuitka_scanner_config_data_patterns_are_exact_and_owned() -> None:
    root, records = _configuration()
    record = records["Virus_Scan.scanners.config"]
    assert set(record) == {"module-name", "data-files"}
    assert record["module-name"] == "Virus_Scan.scanners.config"
    data_files = record["data-files"]
    assert type(data_files) is list and len(data_files) == 1
    selector = data_files[0]
    assert type(selector) is dict and set(selector) == {"patterns"}
    assert tuple(selector["patterns"]) == _SCANNER_CONFIG_DATA_PATTERNS
    module_root = root / "Virus_Scan" / "scanners" / "config"
    for relative in _SCANNER_CONFIG_DATA_PATTERNS:
        path = module_root / relative
        assert path.is_file()
        assert not path.is_symlink()


def test_phase23_nuitka_parser_data_patterns_are_exact_and_owned() -> None:
    root, records = _configuration()
    record = records["Virus_Scan.scanners.static_program_analysis"]
    assert set(record) == {"module-name", "data-files", "dlls"}
    assert record["module-name"] == "Virus_Scan.scanners.static_program_analysis"
    data_files = record["data-files"]
    assert type(data_files) is list and len(data_files) == 1
    selector = data_files[0]
    assert type(selector) is dict and set(selector) == {"patterns"}
    assert tuple(selector["patterns"]) == _DATA_PATTERNS
    module_root = root / "Virus_Scan" / "scanners" / "static_program_analysis"
    for relative in _DATA_PATTERNS:
        path = module_root / relative
        assert path.is_file()
        assert not path.is_symlink()


def test_phase23_nuitka_node_executable_selectors_are_platform_exact() -> None:
    root, records = _configuration()
    record = records["Virus_Scan.scanners.static_program_analysis"]
    dlls = record["dlls"]
    assert type(dlls) is list and len(dlls) == 2
    linux, windows = dlls
    assert linux == {
        "from_filenames": {
            "relative_path": "typescript_parser_resource/node_runtime/linux-x86_64",
            "prefixes": ["node"],
            "executable": "yes",
        },
        "dest_path": (
            "Virus_Scan/scanners/static_program_analysis/"
            "typescript_parser_resource/node_runtime/linux-x86_64"
        ),
        "when": "linux and arch_amd64",
    }
    assert windows == {
        "from_filenames": {
            "relative_path": "typescript_parser_resource/node_runtime/windows-x86_64",
            "prefixes": ["node"],
            "suffixes": ["exe"],
            "executable": "yes",
        },
        "dest_path": (
            "Virus_Scan/scanners/static_program_analysis/"
            "typescript_parser_resource/node_runtime/windows-x86_64"
        ),
        "when": "win32 and arch_amd64",
    }
    resource_root = (
        root
        / "Virus_Scan/scanners/static_program_analysis/typescript_parser_resource"
    )
    linux_binary = resource_root / "node_runtime/linux-x86_64/node"
    windows_binary = resource_root / "node_runtime/windows-x86_64/node.exe"
    assert linux_binary.is_file() and windows_binary.is_file()
    assert not linux_binary.is_symlink() and not windows_binary.is_symlink()
    assert os.access(linux_binary, os.X_OK)
    assert hashlib.sha256(windows_binary.read_bytes()).hexdigest() == (
        "c5ff4c736112dd483c750fd4149d30c8a116db1a49b8b3ec88be4b65e6c86c19"
    )


def test_phase23_nuitka_configuration_contains_no_host_runtime_discovery() -> None:
    root, _records = _configuration()
    configuration = (root / "umige.nuitka-package.config.yml").read_text(
        encoding="utf-8"
    )
    frontend = (
        root
        / "Virus_Scan/scanners/static_program_analysis/javascript_typescript_frontend.py"
    ).read_text(encoding="utf-8")

    for forbidden in ("/usr/bin/node", "/opt/nvm", "shutil.which", "which node"):
        assert forbidden not in configuration
        assert forbidden not in frontend


def test_phase23_nuitka_capstone_core_selector_is_packaged_only() -> None:
    root, records = _configuration()
    record = records["packaged_capstone_5_0_9"]
    assert set(record) == {"module-name", "data-files", "dlls"}
    assert record["data-files"] == [{
        "patterns": [
            "dependency_manifest.json",
            "LICENSE.TXT",
            "provenance/strict_packaged_loader.patch",
        ],
    }]
    assert record["dlls"] == [
        {
            "from_filenames": {
                "relative_path": "capstone/lib",
                "prefixes": ["libcapstone"],
                "suffixes": ["so"],
            },
            "dest_path": "packaged_capstone_5_0_9/capstone/lib",
            "when": "linux and arch_amd64",
        },
        {
            "from_filenames": {
                "relative_path": "capstone/lib",
                "prefixes": ["capstone"],
                "suffixes": ["dll"],
            },
            "dest_path": "packaged_capstone_5_0_9/capstone/lib",
            "when": "win32 and arch_amd64",
        },
    ]
    package_root = root / "packaged_capstone_5_0_9"
    assert (package_root / "dependency_manifest.json").is_file()
    assert (package_root / "LICENSE.TXT").is_file()
    assert (package_root / "provenance/strict_packaged_loader.patch").is_file()
    linux_core = package_root / "capstone/lib/libcapstone.so"
    windows_core = package_root / "capstone/lib/capstone.dll"
    assert linux_core.is_file() and windows_core.is_file()
    assert hashlib.sha256(windows_core.read_bytes()).hexdigest() == (
        "76958e18380023a68fd1714fa2e01c594cc6db1955a07ad6937b66e66dc5d6c3"
    )
    windows_wheel = (
        package_root / "provenance/capstone-5.0.9-py3-none-win_amd64.whl"
    )
    assert windows_wheel.is_file()
    assert hashlib.sha256(windows_wheel.read_bytes()).hexdigest() == (
        "732cedbbb56d42e723f14d7af6387f1454194a820b4b96b56d1e53f865ef85d0"
    )


def test_phase23_nuitka_exact_runtime_finalizer_is_single_build_owner() -> None:
    root = Path(__file__).resolve().parents[2]
    plugin = root / "tools/nuitka_packaging/exact_runtime_plugin.py"
    finalizer = root / "tools/nuitka_packaging/exact_runtime_finalizer.py"
    plugin_source = plugin.read_text(encoding="utf-8")
    finalizer_source = finalizer.read_text(encoding="utf-8")

    assert plugin.is_file() and finalizer.is_file()
    assert plugin_source.count("finalize_exact_packaged_runtimes(") == 1
    assert "onStandaloneDistributionFinished" in plugin_source
    runtime_api_imports = {
        alias.name
        for node in ast.walk(ast.parse(finalizer_source))
        if isinstance(node, ast.ImportFrom) and node.module == "Virus_Scan.runtime.api"
        for alias in node.names
    }
    assert "durable_replace_regular_file" in runtime_api_imports
    assert "durable_replace_regular_file(temporary, target)" in finalizer_source
    assert "os.replace(" not in finalizer_source
    assert "nuitka_noncanonical_runtime_path_present" in finalizer_source
    for forbidden in ("shutil.which", "LD_LIBRARY_PATH", "CAPSTONE_LIBRARY_PATH"):
        assert forbidden not in plugin_source
        assert forbidden not in finalizer_source
