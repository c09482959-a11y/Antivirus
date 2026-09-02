from Virus_Scan.tests.support.static_inventory import parse_python_file, python_files_under, read_python_file

from pathlib import Path
import ast


_FILES_WITH_PUBLIC_OWNER_IMPORTS = (
    "Virus_Scan/models/markov/flow.py",
    "Virus_Scan/models/graph/common.py",
    "Virus_Scan/models/profiles/persistence.py",
    "Virus_Scan/models/profiles/quarantine.py",
    "Virus_Scan/models/profiles/replay_learning.py",
    "Virus_Scan/runtime/config.py",
    "Virus_Scan/runtime/resource_economics.py",
    "Virus_Scan/runtime/scan_dependencies.py",
    "Virus_Scan/publication/json_writer.py",
    "Virus_Scan/publication/json_finalization/compact_record.py",
    "Virus_Scan/publication/json_finalization/scheduler_projection.py",
    "Virus_Scan/publication/json_finalization/streaming.py",
)

_EXPECTED_PUBLIC_TOKENS = (
    ("Virus_Scan/models/markov/flow.py", "canonical_behavior_event_name"),
    ("Virus_Scan/models/profiles/persistence.py", "runtime_worker_shared_persistence_writes_disabled"),
    ("Virus_Scan/models/profiles/replay_learning.py", "runtime_worker_shared_persistence_writes_disabled"),
    ("Virus_Scan/models/profiles/quarantine.py", "profile_corruption_evidence"),
    ("Virus_Scan/runtime/config.py", "int_env"),
    ("Virus_Scan/runtime/resource_economics.py", "float_env"),
    ("Virus_Scan/runtime/scan_dependencies.py", "contract_get_scan_extension"),
    ("Virus_Scan/publication/json_finalization/streaming.py", "contract_make_json_safe"),
)

_ALLOWED_PRIVATE_DEFS = frozenset({
    "__all__",
    "__annotations__",
    "__builtins__",
    "__cached__",
    "__doc__",
    "__file__",
    "__loader__",
    "__name__",
    "__package__",
    "__spec__",
})


def _module_tree(path_text):
    return parse_python_file(Path(path_text))


def test_stage1467_model_runtime_public_imports_do_not_use_private_aliases():
    offenders = []
    for path_text in _FILES_WITH_PUBLIC_OWNER_IMPORTS:
        for node in ast.walk(_module_tree(path_text)):
            if not isinstance(node, ast.ImportFrom):
                continue
            for alias in node.names:
                if alias.name in _ALLOWED_PRIVATE_DEFS:
                    continue
                if alias.name.startswith("_") or (alias.asname or "").startswith("_"):
                    offenders.append((path_text, node.lineno, node.module, alias.name, alias.asname))
    assert offenders == []


def test_stage1467_public_owner_tokens_replace_private_reach_through_aliases():
    missing = []
    for path_text, token in _EXPECTED_PUBLIC_TOKENS:
        text = read_python_file(Path(path_text))
        if token not in text:
            missing.append((path_text, token))
    assert missing == []


def test_stage1467_model_runtime_public_boundaries_have_no_stale_private_alias_tokens():
    stale_tokens = (
        "_behavior_sequence_contract_name",
        "_runtime_program_root",
        "_umige_shared_persistence_worker_writes_disabled",
        "_profile_corruption_evidence",
        "_profile_corruption_quarantine_suffix",
        "_contract_get_scan_extension",
        "_ordered_unique_tags",
        "_contract_make_json_safe",
        "_profile_persistence_state_boundary",
        "_float_env",
        "_int_env",
        "_umige_const_eval_string_node",
    )
    offenders = []
    for path_text in _FILES_WITH_PUBLIC_OWNER_IMPORTS:
        text = read_python_file(Path(path_text))
        for token in stale_tokens:
            if token in text:
                offenders.append((path_text, token))
    assert offenders == []

_DETECTION_PUBLIC_OWNER_IMPORT_FILES = (
    "Virus_Scan/detection/contracts/binary_predicates.py",
    "Virus_Scan/detection/contracts/tag_validation.py",
    "Virus_Scan/detection/profiles/profile_policy.py",
)


def test_stage1467_detection_profile_contracts_do_not_use_private_import_aliases():
    offenders = []
    for path_text in _DETECTION_PUBLIC_OWNER_IMPORT_FILES:
        for node in ast.walk(_module_tree(path_text)):
            if not isinstance(node, ast.ImportFrom):
                continue
            for alias in node.names:
                if alias.name.startswith("_") or (alias.asname or "").startswith("_"):
                    offenders.append((path_text, node.lineno, node.module, alias.name, alias.asname))
    assert offenders == []


def test_stage1467_detection_profile_contracts_have_no_stale_private_alias_tokens():
    stale_tokens = (
        "_strict_fast_entropy",
        "_is_renpy_bytecode_path",
        "_renpy_bytecode_identity_tags",
        "_apply_renpy_updater_baseline",
        "_renpy_updater_behavior_abuse_tags",
        "_renpy_updater_has_hard_anchor",
        "_suppress_renpy_bytecode_noise",
    )
    offenders = []
    for path_text in _DETECTION_PUBLIC_OWNER_IMPORT_FILES:
        text = read_python_file(Path(path_text))
        for token in stale_tokens:
            if token in text:
                offenders.append((path_text, token))
    assert offenders == []


def test_stage1793_dead_detection_profile_bytecode_identity_surface_stays_deleted():
    profile_policy = read_python_file(Path("Virus_Scan/detection/profiles/profile_policy.py"))

    assert not Path("Virus_Scan/detection/profiles/renpy/bytecode_identity.py").exists()
    assert "profile_bytecode_identity_tags" not in profile_policy
    assert "renpy_bytecode_identity_tags" not in profile_policy


_DETECTION_MODELISH_IMPORT_ROOTS = (
    "Virus_Scan/detection/contracts",
    "Virus_Scan/detection/profiles",
    "Virus_Scan/detection/scoring",
    "Virus_Scan/detection/enrichment",
)


def test_stage1467_detection_modelish_scopes_have_no_private_import_aliases():
    offenders = []
    for root_text in _DETECTION_MODELISH_IMPORT_ROOTS:
        for path in python_files_under(root_text):
            for node in ast.walk(_module_tree(str(path))):
                if not isinstance(node, ast.ImportFrom):
                    continue
                for alias in node.names:
                    if alias.name == "__all__":
                        continue
                    if alias.name.startswith("_") or (alias.asname or "").startswith("_"):
                        offenders.append((str(path), node.lineno, node.module, alias.name, alias.asname))
    assert offenders == []
